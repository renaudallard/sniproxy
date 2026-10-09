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
 * shared listener socket, from the local address the client sent to.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>
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
#include "tls.h"
#include "logger.h"
#include "fd_util.h"
#include "util.h"

enum udp_session_state {
    UDP_VALIDATING,     /* awaiting a second datagram from the same source */
    UDP_RESOLVING,
    UDP_CONNECTED,
};

struct UDPSession {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int server_fd;              /* per-session connected socket */
    int holds_socket_budget;    /* counted by connections_udp_socket_acquire() */
    int per_ip_counted;         /* counted in the per-IP UDP session counts */
    struct sockaddr_storage local_addr; /* where the client sent to */
    socklen_t local_addr_len;   /* 0 when sent from the listener's own */
    struct ev_io server_watcher;
    struct ev_timer idle_timer;
    struct Listener *listener;
    char *hostname;
    size_t hostname_len;
    char *pending_dgram;        /* saved during DNS resolution */
    size_t pending_dgram_len;
    struct ResolvQuery *query_handle;
    struct UDPSession *next;    /* hash chain */
    TAILQ_ENTRY(UDPSession) validating_entries; /* while UDP_VALIDATING */
    uint32_t addr_hash;
    enum udp_session_state state;
};

struct udp_resolv_cb_data {
    struct UDPSession *session;
    struct Address *address;
    struct ev_loop *loop;
    /* The query's slot under the DNS limits, released with the query by
     * udp_free_resolv_cb_data() once the lookup ends, as it may outlive
     * the session. */
    int dns_slot;
    struct DnsClientUsageEntry *dns_client_usage;
};

static struct UDPSession *session_table[UDP_SESSION_BUCKETS];
static size_t session_count;
/* Sessions still waiting for their second datagram, oldest first */
static TAILQ_HEAD(, UDPSession) validating_sessions =
    TAILQ_HEAD_INITIALIZER(validating_sessions);
static uint64_t udp_hash_key;

static struct UDPSession *udp_session_lookup(const struct sockaddr_storage *addr,
        socklen_t addr_len, uint32_t hash, const struct Listener *listener);
static struct UDPSession *udp_session_create(struct Listener *listener,
        const struct sockaddr_storage *addr, socklen_t addr_len,
        uint32_t hash, struct ev_loop *loop);
static void udp_session_destroy(struct UDPSession *, struct ev_loop *);
static int udp_session_charge_per_ip(struct UDPSession *);
static socklen_t udp_datagram_dst(struct msghdr *, struct sockaddr_storage *);
static int udp_send_from(int, const void *, size_t, const struct UDPSession *);

/* Room for the destination address of a datagram */
union udp_control {
    struct cmsghdr hdr;
    unsigned char buf[256];
};
static void udp_parse_and_resolve(struct UDPSession *, const char *, size_t,
        struct ev_loop *);
static void udp_connect_server(struct UDPSession *, struct ev_loop *);
static void udp_resolv_cb(struct Address *, void *);
static void udp_free_resolv_cb_data(void *);
static void udp_server_cb(struct ev_loop *, struct ev_io *, int);
static int udp_server_recv_one(struct ev_loop *, struct UDPSession *);
static int udp_recv_one(struct ev_loop *, struct Listener *, int);
static void udp_session_idle_cb(struct ev_loop *, struct ev_timer *, int);
static uint32_t udp_hash_addr(const struct sockaddr_storage *, socklen_t);
static int udp_sockaddr_equal(const struct sockaddr_storage *, socklen_t,
        const struct sockaddr_storage *, socklen_t);


void
udp_init_sessions(void) {
    memset(session_table, 0, sizeof(session_table));
    session_count = 0;
    TAILQ_INIT(&validating_sessions);
    arc4random_buf(&udp_hash_key, sizeof(udp_hash_key));
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

/* Re-add every live session to the per-IP connection counts. Used after
 * the counts have been dropped because their keying changed, so that the
 * sessions still hold a reference when they are later torn down. */
void
udp_sessions_recount_per_ip(void) {
    for (size_t i = 0; i < UDP_SESSION_BUCKETS; i++)
        for (struct UDPSession *s = session_table[i]; s != NULL; s = s->next)
            if (s->per_ip_counted)
                connections_udp_session_count_increment(&s->client_addr);
}

void
udp_recv_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct Listener *listener = (struct Listener *)w->data;

    if (!(revents & EV_READ))
        return;

    for (int i = 0; i < UDP_READ_BATCH; i++)
        if (!udp_recv_one(loop, listener, w->fd))
            break;
}

/* Read and handle one datagram from a listener socket. Returns 0 when
 * there was none to read. */
static int
udp_recv_one(struct ev_loop *loop, struct Listener *listener, int fd) {
    char buf[UDP_MAX_DGRAM];
    struct sockaddr_storage client_addr;
    struct iovec iov = { buf, sizeof(buf) };
    union udp_control control;
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &client_addr;
    msg.msg_namelen = sizeof(client_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0)
        return 0;
    if (n == 0)
        return 1;
    socklen_t addr_len = msg.msg_namelen;

    uint32_t hash = udp_hash_addr(&client_addr, addr_len);
    struct UDPSession *session = udp_session_lookup(&client_addr, addr_len,
            hash, listener);

    if (session != NULL) {
        /* In VALIDATING state, switch the timer's repeat to the normal
         * idle timeout before the (single) ev_timer_again reset below. */
        if (session->state == UDP_VALIDATING)
            session->idle_timer.repeat = UDP_DEFAULT_IDLE_TIMEOUT;
        ev_timer_again(loop, &session->idle_timer);

        switch (session->state) {
        case UDP_CONNECTED:
            /* Forward datagram to server */
            if (send(session->server_fd, buf, (size_t)n, 0) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    debug("UDP send to server failed: %s", strerror(errno));
            }
            break;
        case UDP_VALIDATING:
            /* A second datagram from the same (IP, port) ends validation.
             * It is not compared with the first, so this stops single
             * spoofed packets, not an attacker who forges two. Repeat
             * already swapped to idle timeout above. */
            if (!udp_session_charge_per_ip(session)) {
                udp_session_destroy(session, loop);
                return 1;
            }
            udp_parse_and_resolve(session, buf, (size_t)n, loop);
            break;
        case UDP_RESOLVING:
            /* Drop; DTLS client will retransmit after resolution */
            break;
        }
        return 1;
    }

    /* ACL check */
    if (!listener_acl_allows(listener, &client_addr)) {
        char client[INET6_ADDRSTRLEN + 8];
        debug("UDP connection from %s denied by ACL",
                display_sockaddr(&client_addr, addr_len,
                        client, sizeof(client)));
        return 1;
    }

    /* New sessions have a per-IP rate of their own, apart from that of
     * TCP connections: a forged datagram must not use up the allowance of
     * the address it names. It keeps one source from filling the session
     * table. */
    if (!connections_udp_session_rate_limit_allow(&client_addr, ev_now(loop))) {
        debug("UDP session rate limited");
        return 1;
    }

    if (session_count >= UDP_MAX_SESSIONS) {
        /* Make room by dropping the session that has waited longest for
         * its second datagram, so that spoofed first datagrams cannot
         * lock every new client out until they expire. */
        struct UDPSession *oldest = TAILQ_FIRST(&validating_sessions);

        if (oldest == NULL) {
            debug("UDP session limit (%d) reached, dropping datagram",
                    UDP_MAX_SESSIONS);
            return 1;
        }
        udp_session_destroy(oldest, loop);
    }

    session = udp_session_create(listener, &client_addr, addr_len, hash, loop);
    if (session == NULL)
        return 1;
    session->local_addr_len = udp_datagram_dst(&msg, &session->local_addr);

    /* Session starts in UDP_VALIDATING state. The datagram is not forwarded
     * yet; we wait for a second one from the same (IP, port), which DTLS
     * clients send by design (RFC 6347 section 4.2.4). A single spoofed
     * packet therefore never reaches a backend; an attacker who forges
     * more than one is left to the backend's own cookie exchange. */

    return 1;
}

static void
udp_server_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct UDPSession *session = (struct UDPSession *)w->data;

    if (!(revents & EV_READ))
        return;

    for (int i = 0; i < UDP_READ_BATCH; i++)
        if (!udp_server_recv_one(loop, session))
            break;
}

/* Pass one datagram from the backend on to the client. Returns 0 when
 * there was none to read or the session is gone. */
static int
udp_server_recv_one(struct ev_loop *loop, struct UDPSession *session) {
    char buf[UDP_MAX_DGRAM];

    ssize_t n = recv(session->server_fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        debug("UDP recv from server failed: %s", strerror(errno));
        udp_session_destroy(session, loop);
        return 0;
    }

    /* n == 0 is a valid zero-length UDP datagram, not a connection close */

    /* Send response back to client via listener socket.
     * Use the listener's watcher fd rather than caching it, so that
     * SIGHUP reload closing an old listener makes us fail safely
     * with EBADF instead of writing to a recycled fd number. */
    int listener_fd = session->listener->watcher.fd;
    if (listener_fd < 0)
        return 0;

    if (udp_send_from(listener_fd, buf, (size_t)n, session) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            debug("UDP send to client failed: %s", strerror(errno));
    }

    /* The idle timer is left alone: only the client keeps a session
     * alive, as its address may be forged, and a backend sending on its
     * own would otherwise have sniproxy send to that address forever. */

    return 1;
}

/*
 * The local address a datagram was sent to, from the ancillary data a
 * wildcard listener asks for, see listener_recv_dst_addr(). Returns its
 * length, or 0 when there is none.
 */
static socklen_t
udp_datagram_dst(struct msghdr *msg, struct sockaddr_storage *dst) {
    struct cmsghdr *cmsg;

    memset(dst, 0, sizeof(*dst));
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
#ifdef IPV6_RECVPKTINFO
        if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                cmsg->cmsg_type == IPV6_PKTINFO) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;
            struct in6_pktinfo info;

            memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = info.ipi6_addr;
            return sizeof(*sin6);
        }
#endif
#if defined(IP_PKTINFO)
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct sockaddr_in *sin = (struct sockaddr_in *)dst;
            struct in_pktinfo info;

            memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
            sin->sin_family = AF_INET;
            /* macOS fills only ipi_addr, the datagram's destination */
            sin->sin_addr = info.ipi_spec_dst.s_addr != htonl(INADDR_ANY) ?
                    info.ipi_spec_dst : info.ipi_addr;
            return sizeof(*sin);
        }
#elif defined(IP_RECVDSTADDR) && defined(IP_SENDSRCADDR)
        if (cmsg->cmsg_level == IPPROTO_IP &&
                cmsg->cmsg_type == IP_RECVDSTADDR) {
            struct sockaddr_in *sin = (struct sockaddr_in *)dst;

            memcpy(&sin->sin_addr, CMSG_DATA(cmsg), sizeof(sin->sin_addr));
            sin->sin_family = AF_INET;
            return sizeof(*sin);
        }
#endif
    }

    return 0;
}

/*
 * Send a reply to the session's client from the address the client sent
 * to. One the system no longer accepts as a source, such as an expired
 * temporary IPv6 address, falls back to the address the kernel picks.
 */
static int
udp_send_from(int fd, const void *buf, size_t len,
        const struct UDPSession *session) {
    struct iovec iov = { (void *)(uintptr_t)buf, len };
    union udp_control control;
    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)(uintptr_t)&session->client_addr;
    msg.msg_namelen = session->client_addr_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memset(&control, 0, sizeof(control));
    msg.msg_control = control.buf;
    cmsg = (struct cmsghdr *)control.buf;

    if (session->local_addr_len == 0) {
        msg.msg_control = NULL;
#ifdef IPV6_RECVPKTINFO
    } else if (session->local_addr.ss_family == AF_INET6) {
        struct in6_pktinfo info;

        memset(&info, 0, sizeof(info));
        info.ipi6_addr = ((const struct sockaddr_in6 *)&session->local_addr)->sin6_addr;
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        msg.msg_controllen = CMSG_SPACE(sizeof(info));
#endif
#if defined(IP_PKTINFO)
    } else if (session->local_addr.ss_family == AF_INET) {
        struct in_pktinfo info;

        memset(&info, 0, sizeof(info));
        info.ipi_spec_dst = ((const struct sockaddr_in *)&session->local_addr)->sin_addr;
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        msg.msg_controllen = CMSG_SPACE(sizeof(info));
#elif defined(IP_RECVDSTADDR) && defined(IP_SENDSRCADDR)
    } else if (session->local_addr.ss_family == AF_INET) {
        const struct in_addr *src =
                &((const struct sockaddr_in *)&session->local_addr)->sin_addr;

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(*src));
        memcpy(CMSG_DATA(cmsg), src, sizeof(*src));
        msg.msg_controllen = CMSG_SPACE(sizeof(*src));
#endif
    } else {
        msg.msg_control = NULL;
    }

    ssize_t sent = sendmsg(fd, &msg, 0);
    if (sent < 0 && msg.msg_control != NULL &&
            (errno == EADDRNOTAVAIL || errno == EINVAL)) {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        sent = sendmsg(fd, &msg, 0);
    }

    return sent < 0 ? -1 : 0;
}

static struct UDPSession *
udp_session_lookup(const struct sockaddr_storage *addr, socklen_t addr_len,
        uint32_t hash, const struct Listener *listener) {
    uint32_t bucket = hash & (UDP_SESSION_BUCKETS - 1);
    struct UDPSession *s = session_table[bucket];

    while (s != NULL) {
        /* The session table is global, so also match the receiving listener:
         * a datagram from the same client (IP, port) arriving on a different
         * DTLS listener must not reuse another listener's session, backend or
         * routing policy. */
        if (s->addr_hash == hash && s->listener == listener &&
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
    s->state = UDP_VALIDATING;
    TAILQ_INSERT_TAIL(&validating_sessions, s, validating_entries);

    ev_init(&s->server_watcher, udp_server_cb);
    s->server_watcher.data = s;

    ev_init(&s->idle_timer, udp_session_idle_cb);
    s->idle_timer.repeat = UDP_VALIDATION_TIMEOUT;
    s->idle_timer.data = s;
    ev_timer_again(loop, &s->idle_timer);

    uint32_t bucket = hash & (UDP_SESSION_BUCKETS - 1);
    s->next = session_table[bucket];
    session_table[bucket] = s;
    session_count++;

    return s;
}

/*
 * Count a session against its client's per-IP limit of UDP sessions, apart
 * from its TCP connections, once its second datagram has come from the
 * same address and port. Returns 0 if the limit refuses it.
 */
static int
udp_session_charge_per_ip(struct UDPSession *session) {
    if (!connections_udp_session_count_allow(&session->client_addr)) {
        debug("UDP session denied by per-IP connection limit");
        return 0;
    }

    connections_udp_session_count_increment(&session->client_addr);
    session->per_ip_counted = 1;
    return 1;
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
    if (session->state == UDP_VALIDATING)
        TAILQ_REMOVE(&validating_sessions, session, validating_entries);
    if (session->per_ip_counted)
        connections_udp_session_count_decrement(&session->client_addr);

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
    if (session->holds_socket_budget)
        connections_udp_socket_release();

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

    /* Validation is over: from here the session resolves its backend,
     * connects to it or goes away. */
    TAILQ_REMOVE(&validating_sessions, session, validating_entries);
    session->state = UDP_RESOLVING;

    int result = proto->parse_packet(data, data_len, &hostname);

    if (result == TLS_ERR_CLIENT_RENEGOTIATION) {
        /* As on TCP: a renegotiation hello cannot start a session, so
         * the fallback would only get a handshake it cannot finish. */
        char client[INET6_ADDRSTRLEN + 8];
        notice("UDP: client %s attempted DTLS renegotiation, dropping",
                display_sockaddr(&session->client_addr,
                        session->client_addr_len,
                        client, sizeof(client)));
        udp_session_destroy(session, loop);
        return;
    }

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

    /* Save the datagram for forwarding after resolution.
     * Cap the saved size to UDP_MAX_PENDING_DGRAM to limit memory when
     * many sessions are in RESOLVING state simultaneously. A DTLS
     * ClientHello is typically 200-600 bytes. If the datagram exceeds
     * the cap, skip saving; the client will retransmit after the backend
     * connection is established. */
    if (data_len <= UDP_MAX_PENDING_DGRAM) {
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
    }

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
            struct sockaddr_storage client;
            (void)sockaddr_unmap_ipv4(&session->client_addr,
                    session->client_addr_len, &client);
            switch (client.ss_family) {
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

        /* Count this lookup against the global and per-client DNS limits,
         * the same caps the TCP path enforces, so UDP/DTLS cannot drive
         * unbounded concurrent upstream resolutions. */
        enum dns_acquire_status dns_status =
                connections_dns_query_acquire_addr(&session->client_addr, 1,
                        &cb_data->dns_client_usage);
        if (dns_status != DNS_ACQUIRE_OK) {
            notice("UDP: DNS query for %s rejected: %s limit reached", hn,
                    dns_status == DNS_ACQUIRE_GLOBAL_LIMIT ? "global"
                            : "per-client");
            free(cb_data->address);
            free(cb_data);
            udp_session_destroy(session, loop);
            return;
        }
        cb_data->dns_slot = 1;

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
    if (cb_data->dns_slot)
        connections_dns_query_release_entry(cb_data->dns_client_usage, 1);
    free(cb_data->address);
    free(cb_data);
}

static void
udp_connect_server(struct UDPSession *session, struct ev_loop *loop) {
    if (sockaddr_is_multicast(&session->server_addr)) {
        char server[INET6_ADDRSTRLEN + 8];
        char client[INET6_ADDRSTRLEN + 8];
        warn("UDP: refusing multicast backend address %s for %.*s from %s",
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

    /* The backend socket counts against max_connections, as TCP ones do,
     * so that sessions cannot use up the descriptors it leaves. */
    if (!connections_udp_socket_acquire()) {
        static ev_tstamp last_logged;
        if (ev_now(loop) - last_logged >= 1.0) {
            char client[INET6_ADDRSTRLEN + 8];
            notice("UDP: connection limit reached, dropping session from %s",
                    display_sockaddr(&session->client_addr,
                            session->client_addr_len,
                            client, sizeof(client)));
            last_logged = ev_now(loop);
        }
        udp_session_destroy(session, loop);
        return;
    }
    session->holds_socket_budget = 1;

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

    /* Source address binding - fail closed so a privilege or
     * configuration failure cannot silently leak the proxy's own source
     * address to the backend instead of the client address. An IPv4
     * client of a dual-stack listener is bound as plain IPv4. */
    if (session->listener->transparent_proxy) {
#ifdef IP_TRANSPARENT
        struct sockaddr_storage source;
        socklen_t source_len = sockaddr_unmap_ipv4(&session->client_addr,
                session->client_addr_len, &source);
        int on = 1;
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0) {
            err("UDP: setsockopt IP_TRANSPARENT: %s", strerror(errno));
            close(fd);
            udp_session_destroy(session, loop);
            return;
        }
        if (bind(fd, (struct sockaddr *)&source, source_len) < 0) {
            err("UDP: bind transparent source: %s", strerror(errno));
            close(fd);
            udp_session_destroy(session, loop);
            return;
        }
#endif
    } else if (session->listener->source_address != NULL) {
        if (bind(fd, address_sa(session->listener->source_address),
                address_sa_len(session->listener->source_address)) < 0) {
            err("UDP: bind source address: %s", strerror(errno));
            close(fd);
            udp_session_destroy(session, loop);
            return;
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
            case UDP_VALIDATING: state_str = "VALIDATING"; break;
            case UDP_RESOLVING:  state_str = "RESOLVING"; break;
            case UDP_CONNECTED:  state_str = "CONNECTED"; break;
            default:             state_str = "UNKNOWN"; break;
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
    (void)addr_len;

    switch (addr->ss_family) {
    case AF_INET: {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        uint64_t v = ((uint64_t)ntohl(in->sin_addr.s_addr) << 16) |
                ntohs(in->sin_port);

        return hash_mix64_to_32(udp_hash_key ^ v);
    }
    case AF_INET6: {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        uint64_t words[2];

        memcpy(words, &in6->sin6_addr, sizeof(words));
        uint64_t h = hash_mix64(udp_hash_key ^ words[0]);
        h = hash_mix64(h ^ words[1]);
        return hash_mix64_to_32(h ^ ((uint64_t)in6->sin6_scope_id << 16 |
                    ntohs(in6->sin6_port)));
    }
    default:
        return 0;
    }
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
        /* The same link-local address may be in use on two links */
        return a6->sin6_port == b6->sin6_port &&
            a6->sin6_scope_id == b6->sin6_scope_id &&
            memcmp(&a6->sin6_addr, &b6->sin6_addr,
                    sizeof(a6->sin6_addr)) == 0;
    }
    default:
        return 0;
    }
}
