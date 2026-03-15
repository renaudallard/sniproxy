/*
 * Copyright (c) 2026, Renaud Allard <renaud@allard.it>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * UDP session manager for DTLS proxying.
 *
 * Each unique (client IP, client port) pair maps to a UDPSession that holds
 * a connected server socket.  Datagrams from the client are forwarded to the
 * server via this socket; responses are sent back to the client via the
 * shared listener socket using sendto().
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#ifdef HAVE_BSD_UNISTD_H
#include <bsd/unistd.h>
#endif
#include "udp_connection.h"
#include "connection.h"
#include "listener.h"
#include "address.h"
#include "resolv.h"
#include "protocol.h"
#include "logger.h"
#include "fd_util.h"

enum udp_session_state {
    UDP_NEW,
    UDP_RESOLVING,
    UDP_CONNECTED,
};

struct UDPSession {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int server_fd;              /* per-session connected socket */
    struct ev_io server_watcher;
    struct ev_timer idle_timer;
    struct Listener *listener;
    char *hostname;
    size_t hostname_len;
    char *pending_dgram;        /* saved during DNS resolution */
    size_t pending_dgram_len;
    struct ResolvQuery *query_handle;
    struct UDPSession *next;    /* hash chain */
    uint32_t addr_hash;
    enum udp_session_state state;
};

struct udp_resolv_cb_data {
    struct UDPSession *session;
    struct Address *address;
    struct ev_loop *loop;
};

static struct UDPSession *session_table[UDP_SESSION_BUCKETS];
static size_t session_count;
static uint32_t udp_hash_seed;

static struct UDPSession *udp_session_lookup(const struct sockaddr_storage *addr,
        socklen_t addr_len, uint32_t hash);
static struct UDPSession *udp_session_create(struct Listener *listener,
        const struct sockaddr_storage *addr, socklen_t addr_len,
        uint32_t hash, struct ev_loop *loop);
static void udp_session_destroy(struct UDPSession *, struct ev_loop *);
static void udp_parse_and_resolve(struct UDPSession *, const char *, size_t,
        struct ev_loop *);
static void udp_connect_server(struct UDPSession *, struct ev_loop *);
static void udp_resolv_cb(struct Address *, void *);
static void udp_free_resolv_cb_data(void *);
static void udp_server_cb(struct ev_loop *, struct ev_io *, int);
static void udp_session_idle_cb(struct ev_loop *, struct ev_timer *, int);
static uint32_t udp_hash_addr(const struct sockaddr_storage *, socklen_t);
static int udp_sockaddr_equal(const struct sockaddr_storage *, socklen_t,
        const struct sockaddr_storage *, socklen_t);


void
udp_init_sessions(void) {
    memset(session_table, 0, sizeof(session_table));
    session_count = 0;
    udp_hash_seed = arc4random();
}

void
udp_free_sessions(struct ev_loop *loop) {
    for (size_t i = 0; i < UDP_SESSION_BUCKETS; i++) {
        struct UDPSession *s = session_table[i];
        while (s != NULL) {
            struct UDPSession *next = s->next;
            udp_session_destroy(s, loop);
            s = next;
        }
        session_table[i] = NULL;
    }
    session_count = 0;
}

void
udp_recv_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct Listener *listener = (struct Listener *)w->data;
    char buf[UDP_MAX_DGRAM];
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);

    if (!(revents & EV_READ))
        return;

    ssize_t n = recvfrom(w->fd, buf, sizeof(buf), 0,
            (struct sockaddr *)&client_addr, &addr_len);
    if (n <= 0)
        return;

    uint32_t hash = udp_hash_addr(&client_addr, addr_len);
    struct UDPSession *session = udp_session_lookup(&client_addr, addr_len,
            hash);

    if (session != NULL) {
        /* Reset idle timer */
        ev_timer_again(loop, &session->idle_timer);

        switch (session->state) {
        case UDP_CONNECTED:
            /* Forward datagram to server */
            if (send(session->server_fd, buf, (size_t)n, 0) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    debug("UDP send to server failed: %s", strerror(errno));
            }
            break;
        case UDP_RESOLVING:
            /* Drop; DTLS client will retransmit after resolution */
            break;
        case UDP_NEW:
            break;
        }
        return;
    }

    /* ACL check */
    if (!listener_acl_allows(listener, &client_addr)) {
        char client[INET6_ADDRSTRLEN + 8];
        debug("UDP connection from %s denied by ACL",
                display_sockaddr(&client_addr, addr_len,
                        client, sizeof(client)));
        return;
    }

    if (session_count >= UDP_MAX_SESSIONS) {
        debug("UDP session limit (%d) reached, dropping datagram",
                UDP_MAX_SESSIONS);
        return;
    }

    session = udp_session_create(listener, &client_addr, addr_len, hash, loop);
    if (session == NULL)
        return;

    udp_parse_and_resolve(session, buf, (size_t)n, loop);
}

static void
udp_server_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct UDPSession *session = (struct UDPSession *)w->data;
    char buf[UDP_MAX_DGRAM];

    if (!(revents & EV_READ))
        return;

    ssize_t n = recv(session->server_fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        debug("UDP recv from server failed: %s", strerror(errno));
        udp_session_destroy(session, loop);
        return;
    }

    /* n == 0 is a valid zero-length UDP datagram, not a connection close */

    /* Send response back to client via listener socket.
     * Use the listener's watcher fd rather than caching it, so that
     * SIGHUP reload closing an old listener makes us fail safely
     * with EBADF instead of writing to a recycled fd number. */
    int listener_fd = session->listener->watcher.fd;
    if (listener_fd < 0)
        return;

    if (sendto(listener_fd, buf, (size_t)n, 0,
            (struct sockaddr *)&session->client_addr,
            session->client_addr_len) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            debug("UDP sendto client failed: %s", strerror(errno));
    }

    ev_timer_again(loop, &session->idle_timer);
}

static struct UDPSession *
udp_session_lookup(const struct sockaddr_storage *addr, socklen_t addr_len,
        uint32_t hash) {
    uint32_t bucket = hash & (UDP_SESSION_BUCKETS - 1);
    struct UDPSession *s = session_table[bucket];

    while (s != NULL) {
        if (s->addr_hash == hash &&
                udp_sockaddr_equal(&s->client_addr, s->client_addr_len,
                        addr, addr_len))
            return s;
        s = s->next;
    }

    return NULL;
}

static struct UDPSession *
udp_session_create(struct Listener *listener,
        const struct sockaddr_storage *addr, socklen_t addr_len,
        uint32_t hash, struct ev_loop *loop) {
    struct UDPSession *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        err("calloc: %s", strerror(errno));
        return NULL;
    }

    memcpy(&s->client_addr, addr, addr_len);
    s->client_addr_len = addr_len;
    s->listener = listener_ref_get(listener);
    s->server_fd = -1;
    s->addr_hash = hash;
    s->state = UDP_NEW;

    ev_init(&s->server_watcher, udp_server_cb);
    s->server_watcher.data = s;

    ev_init(&s->idle_timer, udp_session_idle_cb);
    s->idle_timer.repeat = UDP_DEFAULT_IDLE_TIMEOUT;
    s->idle_timer.data = s;
    ev_timer_again(loop, &s->idle_timer);

    uint32_t bucket = hash & (UDP_SESSION_BUCKETS - 1);
    s->next = session_table[bucket];
    session_table[bucket] = s;
    session_count++;

    return s;
}

static void
udp_session_destroy(struct UDPSession *session, struct ev_loop *loop) {
    if (session == NULL)
        return;

    /* Remove from hash table */
    uint32_t bucket = session->addr_hash & (UDP_SESSION_BUCKETS - 1);
    struct UDPSession **pp = &session_table[bucket];
    while (*pp != NULL) {
        if (*pp == session) {
            *pp = session->next;
            break;
        }
        pp = &(*pp)->next;
    }
    session_count--;

    /* Cancel pending DNS query */
    if (session->query_handle != NULL) {
        resolv_cancel(session->query_handle);
        session->query_handle = NULL;
    }

    /* Stop watchers */
    ev_timer_stop(loop, &session->idle_timer);
    if (session->server_fd >= 0) {
        ev_io_stop(loop, &session->server_watcher);
        close(session->server_fd);
    }

    /* Log */
    if (session->hostname != NULL) {
        char client[INET6_ADDRSTRLEN + 8];
        info("UDP session closed: %s -> %.*s",
                display_sockaddr(&session->client_addr,
                        session->client_addr_len,
                        client, sizeof(client)),
                (int)session->hostname_len, session->hostname);
    }

    listener_ref_put(session->listener);
    free(session->hostname);
    free(session->pending_dgram);
    free(session);
}

static void
udp_parse_and_resolve(struct UDPSession *session, const char *data,
        size_t data_len, struct ev_loop *loop) {
    char *hostname = NULL;
    const struct Protocol *proto = session->listener->protocol;

    int result = proto->parse_packet(data, data_len, &hostname);

    if (result > 0) {
        session->hostname = hostname;
        session->hostname_len = (size_t)result;
    } else {
        /* No hostname found, will use fallback */
        session->hostname = NULL;
        session->hostname_len = 0;
    }

    struct LookupResult lookup = listener_lookup_server_address(
            session->listener, session->hostname, session->hostname_len);

    if (lookup.address == NULL) {
        char client[INET6_ADDRSTRLEN + 8];
        notice("UDP: no backend for %s from %s",
                session->hostname ? session->hostname : "(no SNI)",
                display_sockaddr(&session->client_addr,
                        session->client_addr_len,
                        client, sizeof(client)));
        udp_session_destroy(session, loop);
        return;
    }

    /* Save the datagram for forwarding after resolution */
    session->pending_dgram = malloc(data_len);
    if (session->pending_dgram == NULL) {
        err("malloc: %s", strerror(errno));
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        udp_session_destroy(session, loop);
        return;
    }
    memcpy(session->pending_dgram, data, data_len);
    session->pending_dgram_len = data_len;

    if (address_is_hostname(lookup.address)) {
        /* Need DNS resolution */
        struct udp_resolv_cb_data *cb_data = calloc(1, sizeof(*cb_data));
        if (cb_data == NULL) {
            err("calloc: %s", strerror(errno));
            if (lookup.caller_free_address)
                free((void *)lookup.address);
            udp_session_destroy(session, loop);
            return;
        }

        cb_data->session = session;
        cb_data->loop = loop;
        cb_data->address = copy_address(lookup.address);
        if (cb_data->address == NULL) {
            err("copy_address: %s", strerror(errno));
            if (lookup.caller_free_address)
                free((void *)lookup.address);
            free(cb_data);
            udp_session_destroy(session, loop);
            return;
        }

        if (lookup.caller_free_address)
            free((void *)lookup.address);

        const char *hn = address_hostname(cb_data->address);
        if (hn == NULL || hn[0] == '\0') {
            err("UDP: empty hostname from address lookup");
            free(cb_data->address);
            free(cb_data);
            udp_session_destroy(session, loop);
            return;
        }

        int resolv_mode = RESOLV_MODE_DEFAULT;
        if (session->listener->transparent_proxy) {
            switch (session->client_addr.ss_family) {
            case AF_INET:
                resolv_mode = RESOLV_MODE_IPV4_ONLY;
                break;
            case AF_INET6:
                resolv_mode = RESOLV_MODE_IPV6_ONLY;
                break;
            default:
                break;
            }
        }

        session->state = UDP_RESOLVING;
        struct ResolvQuery *qh = resolv_query(hn, resolv_mode, 0,
                udp_resolv_cb, udp_free_resolv_cb_data, cb_data);
        if (qh == NULL) {
            /* resolv_query failed synchronously and already called the
             * callback, which handles cleanup */
            return;
        }
        session->query_handle = qh;
    } else if (address_is_sockaddr(lookup.address)) {
        session->server_addr_len = address_sa_len(lookup.address);
        if ((size_t)session->server_addr_len > sizeof(session->server_addr)) {
            err("UDP: server address too large");
            if (lookup.caller_free_address)
                free((void *)lookup.address);
            udp_session_destroy(session, loop);
            return;
        }
        memcpy(&session->server_addr, address_sa(lookup.address),
                session->server_addr_len);

        if (lookup.caller_free_address)
            free((void *)lookup.address);

        udp_connect_server(session, loop);
    } else {
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        udp_session_destroy(session, loop);
    }
}

static void
udp_resolv_cb(struct Address *result, void *data) {
    struct udp_resolv_cb_data *cb_data = (struct udp_resolv_cb_data *)data;
    struct UDPSession *session = cb_data->session;
    struct ev_loop *loop = cb_data->loop;

    session->query_handle = NULL;

    if (session->state != UDP_RESOLVING) {
        return;
    }

    if (result == NULL) {
        const char *hn = address_hostname(cb_data->address);
        notice("UDP: unable to resolve %s", hn ? hn : "(unknown)");
        udp_session_destroy(session, loop);
        return;
    }

    if (!address_is_sockaddr(result) ||
            address_sa_len(result) > (socklen_t)sizeof(session->server_addr)) {
        err("UDP: resolver returned invalid address");
        udp_session_destroy(session, loop);
        return;
    }

    address_set_port(result, address_port(cb_data->address));

    session->server_addr_len = address_sa_len(result);
    memcpy(&session->server_addr, address_sa(result),
            session->server_addr_len);

    udp_connect_server(session, loop);
}

static void
udp_free_resolv_cb_data(void *data) {
    struct udp_resolv_cb_data *cb_data = (struct udp_resolv_cb_data *)data;
    if (cb_data == NULL)
        return;
    free(cb_data->address);
    free(cb_data);
}

static void
udp_connect_server(struct UDPSession *session, struct ev_loop *loop) {
    if (!backend_acl_allows(&session->server_addr)) {
        char server[INET6_ADDRSTRLEN + 8];
        char client[INET6_ADDRSTRLEN + 8];
        warn("UDP: backend ACL denied connection to %s for %.*s from %s",
                display_sockaddr(&session->server_addr,
                    session->server_addr_len,
                    server, sizeof(server)),
                (int)session->hostname_len,
                session->hostname ? session->hostname : "",
                display_sockaddr(&session->client_addr,
                    session->client_addr_len,
                    client, sizeof(client)));
        udp_session_destroy(session, loop);
        return;
    }

    int fd;
    int socket_type = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif

    fd = socket(session->server_addr.ss_family, socket_type, 0);
    if (fd < 0) {
        err("UDP: socket(): %s", strerror(errno));
        udp_session_destroy(session, loop);
        return;
    }

    if (set_cloexec(fd) < 0) {
        err("UDP: set_cloexec: %s", strerror(errno));
        close(fd);
        udp_session_destroy(session, loop);
        return;
    }

    /* Set nonblocking */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        err("UDP: fcntl O_NONBLOCK: %s", strerror(errno));
        close(fd);
        udp_session_destroy(session, loop);
        return;
    }

    /* Source address binding */
    if (session->listener->transparent_proxy) {
#ifdef IP_TRANSPARENT
        int on = 1;
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0)
            debug("UDP: setsockopt IP_TRANSPARENT: %s", strerror(errno));
        if (bind(fd, (struct sockaddr *)&session->client_addr,
                session->client_addr_len) < 0) {
            debug("UDP: bind transparent source: %s", strerror(errno));
        }
#endif
    } else if (session->listener->source_address != NULL) {
        if (bind(fd, address_sa(session->listener->source_address),
                address_sa_len(session->listener->source_address)) < 0) {
            debug("UDP: bind source address: %s", strerror(errno));
        }
    }

    /* Connect to server (for UDP this sets the default destination) */
    if (connect(fd, (struct sockaddr *)&session->server_addr,
            session->server_addr_len) < 0) {
        err("UDP: connect(): %s", strerror(errno));
        close(fd);
        udp_session_destroy(session, loop);
        return;
    }

    session->server_fd = fd;
    session->state = UDP_CONNECTED;

    ev_io_init(&session->server_watcher, udp_server_cb, fd, EV_READ);
    session->server_watcher.data = session;
    ev_io_start(loop, &session->server_watcher);

    /* Forward the pending datagram */
    if (session->pending_dgram != NULL && session->pending_dgram_len > 0) {
        if (send(fd, session->pending_dgram, session->pending_dgram_len,
                0) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                debug("UDP: send pending datagram: %s", strerror(errno));
        }
        free(session->pending_dgram);
        session->pending_dgram = NULL;
        session->pending_dgram_len = 0;
    }

    char client[INET6_ADDRSTRLEN + 8];
    char server[INET6_ADDRSTRLEN + 8];
    info("UDP session established: %s -> %s [%.*s]",
            display_sockaddr(&session->client_addr, session->client_addr_len,
                    client, sizeof(client)),
            display_sockaddr(&session->server_addr, session->server_addr_len,
                    server, sizeof(server)),
            (int)session->hostname_len,
            session->hostname ? session->hostname : "");
}

static void
udp_session_idle_cb(struct ev_loop *loop,
        struct ev_timer *w, int revents __attribute__((unused))) {
    struct UDPSession *session = (struct UDPSession *)w->data;
    udp_session_destroy(session, loop);
}

void
udp_print_sessions(FILE *file) {
    if (file == NULL)
        return;

    fprintf(file, "\nUDP sessions: %zu active\n", session_count);

    for (size_t i = 0; i < UDP_SESSION_BUCKETS; i++) {
        struct UDPSession *s = session_table[i];
        while (s != NULL) {
            char client[INET6_ADDRSTRLEN + 8];
            char server[INET6_ADDRSTRLEN + 8];
            const char *state_str;

            switch (s->state) {
            case UDP_NEW:       state_str = "NEW"; break;
            case UDP_RESOLVING: state_str = "RESOLVING"; break;
            case UDP_CONNECTED: state_str = "CONNECTED"; break;
            default:            state_str = "UNKNOWN"; break;
            }

            fprintf(file, "  %s -> %s [%.*s] state=%s\n",
                    display_sockaddr(&s->client_addr, s->client_addr_len,
                            client, sizeof(client)),
                    s->server_fd >= 0 ?
                        display_sockaddr(&s->server_addr, s->server_addr_len,
                                server, sizeof(server)) : "(none)",
                    (int)s->hostname_len,
                    s->hostname ? s->hostname : "",
                    state_str);

            s = s->next;
        }
    }
}

/*
 * Hash a sockaddr including IP and port for session lookup.
 * Unlike the TCP rate-limiter which hashes only the IP, UDP sessions
 * are keyed by (IP, port) to distinguish between different clients
 * behind the same NAT.
 */
static uint32_t
udp_hash_addr(const struct sockaddr_storage *addr, socklen_t addr_len) {
    uint32_t h = udp_hash_seed;

    (void)addr_len;

    switch (addr->ss_family) {
    case AF_INET: {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        h ^= (uint32_t)in->sin_addr.s_addr;
        h = (h << 16) | (h >> 16);
        h ^= (uint32_t)in->sin_port;
        h *= 0x9e3779b9u;
        break;
    }
    case AF_INET6: {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        const uint32_t *words = (const uint32_t *)&in6->sin6_addr;
        for (int i = 0; i < 4; i++) {
            h ^= words[i];
            h *= 0x9e3779b9u;
        }
        h ^= (uint32_t)in6->sin6_port;
        h *= 0x9e3779b9u;
        break;
    }
    default:
        break;
    }

    /* Final mix */
    h ^= h >> 16;
    h *= 0x45d9f3bu;
    h ^= h >> 16;

    return h;
}

static int
udp_sockaddr_equal(const struct sockaddr_storage *a, socklen_t alen,
        const struct sockaddr_storage *b, socklen_t blen) {
    (void)alen;
    (void)blen;

    if (a->ss_family != b->ss_family)
        return 0;

    switch (a->ss_family) {
    case AF_INET: {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return a4->sin_port == b4->sin_port &&
            a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    }
    case AF_INET6: {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        return a6->sin6_port == b6->sin6_port &&
            memcmp(&a6->sin6_addr, &b6->sin6_addr,
                    sizeof(a6->sin6_addr)) == 0;
    }
    default:
        return 0;
    }
}
