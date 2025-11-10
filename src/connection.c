/*
 * Copyright (c) 2011-2014, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> /* getaddrinfo */
#include <unistd.h> /* close */
#include <fcntl.h>
#include <arpa/inet.h>
#include <ev.h>
#include <assert.h>
#include <sys/stat.h>
#include "connection.h"
#include "resolv.h"
#include "address.h"
#include "protocol.h"
#include "logger.h"
#include "tls.h"
#include "fd_util.h"


#define IS_TEMPORARY_SOCKERR(_errno) (_errno == EAGAIN || \
                                      _errno == EWOULDBLOCK || \
                                      _errno == EINTR)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define CLIENT_BUFFER_INITIAL_SIZE 16384
#define CLIENT_BUFFER_MIN_SIZE 8192
#define CLIENT_BUFFER_MAX_SIZE (1U << 20)
#define SERVER_BUFFER_INITIAL_SIZE 65536
#define SERVER_BUFFER_MIN_SIZE 32768
#define SERVER_BUFFER_MAX_SIZE (1U << 20)
#define BUFFER_SHRINK_IDLE_SECONDS 1.0
#define CONNECTION_IDLE_TIMEOUT 60.0


struct resolv_cb_data {
    struct Connection *connection;
    const struct Address *address;
    struct ev_loop *loop;
    int cb_free_addr;
};


static TAILQ_HEAD(ConnectionHead, Connection) connections;

static struct ev_timer buffer_shrink_timer;
static struct ev_loop *buffer_shrink_loop;
static int buffer_shrink_timer_configured;

static inline int client_socket_open(const struct Connection *);
static inline int server_socket_open(const struct Connection *);

static void reactivate_watcher(struct ev_loop *, struct ev_io *,
        const struct Buffer *, const struct Buffer *);

static void connection_cb(struct ev_loop *, struct ev_io *, int);
static void resolv_cb(struct Address *, void *);
static void reactivate_watchers(struct Connection *, struct ev_loop *);
static void reactivate_watchers_with_state(struct Connection *, struct ev_loop *, int, int);
static void insert_proxy_v1_header(struct Connection *);
static void parse_client_request(struct Connection *);
static void resolve_server_address(struct Connection *, struct ev_loop *);
static void initiate_server_connect(struct Connection *, struct ev_loop *);
static void close_connection(struct Connection *, struct ev_loop *);
static void close_client_socket(struct Connection *, struct ev_loop *);
static void abort_connection(struct Connection *);
static void close_server_socket(struct Connection *, struct ev_loop *);
static struct Connection *new_connection(struct ev_loop *);
static void log_connection(struct Connection *);
static void log_bad_request(struct Connection *, const char *, size_t, int);
static void free_connection(struct Connection *);
static void print_connection(FILE *, const struct Connection *);
static void free_resolv_cb_data(struct resolv_cb_data *);
static void connection_idle_cb(struct ev_loop *, struct ev_timer *, int);
static void copy_sockaddr_to_storage(struct sockaddr_storage *, const void *, socklen_t);
static void reset_idle_timer(struct Connection *, struct ev_loop *);
static void stop_idle_timer(struct Connection *, struct ev_loop *);

static void buffer_shrink_timer_cb(struct ev_loop *, struct ev_timer *, int);
static void start_buffer_shrink_timer(struct ev_loop *);
static void stop_buffer_shrink_timer(struct ev_loop *);
static void maybe_stop_buffer_shrink_timer(struct ev_loop *);

#define RATE_LIMIT_TABLE_SIZE 1024
#define RATE_LIMIT_IDLE_TTL 300.0
#define RATE_LIMIT_CLEANUP_INTERVAL 60.0

struct RateLimitBucket {
    struct sockaddr_storage addr;
    ev_tstamp last_check;
    double allowance;
    struct RateLimitBucket *next;
    uint32_t addr_hash;
    uint32_t addr_v4;
};

static struct RateLimitBucket *rate_limit_table[RATE_LIMIT_TABLE_SIZE];
static ev_tstamp rate_limit_last_cleanup;
static double per_ip_connection_rate_limit;

static size_t connection_memory_in_use;
static size_t connection_memory_peak;
static size_t connection_active_count;
static size_t connection_peak_count;

static void connection_memory_adjust(ssize_t delta);
static void buffer_memory_observer(ssize_t delta);
static void connection_account_add(void);
static void connection_account_remove(void);

static inline double rate_limit_bucket_capacity(void);
static void rate_limit_reset(void);
static void rate_limit_cleanup(ev_tstamp);
static uint32_t hash_sockaddr_ip(const struct sockaddr_storage *, uint32_t *);
static int sockaddr_equal_ip(const struct sockaddr_storage *,
        const struct sockaddr_storage *);
static int rate_limit_allow_connection(const struct sockaddr_storage *, ev_tstamp);
static const char *format_sockaddr_ip(const struct sockaddr_storage *, char *, size_t);

static int dns_query_acquire(void);
static void dns_query_release(void);


void
init_connections(void) {
    TAILQ_INIT(&connections);
    rate_limit_reset();
    buffer_set_memory_observer(buffer_memory_observer);

    if (BUFFER_SHRINK_IDLE_SECONDS > 0.0) {
        ev_timer_init(&buffer_shrink_timer, buffer_shrink_timer_cb,
                BUFFER_SHRINK_IDLE_SECONDS, BUFFER_SHRINK_IDLE_SECONDS);
        buffer_shrink_timer.data = NULL;
        buffer_shrink_timer_configured = 1;
        buffer_shrink_loop = NULL;
    }
}

/**
 * Accept a new incoming connection
 *
 * Returns 1 on success or 0 on error;
 */
int
accept_connection(struct Listener *listener, struct ev_loop *loop) {
    struct Connection *con = new_connection(loop);
    if (con == NULL) {
        err("new_connection failed");
        return 0;
    }
    con->listener = listener_ref_get(listener);

#ifdef HAVE_ACCEPT4
    int accept_flags = SOCK_NONBLOCK;
#ifdef SOCK_CLOEXEC
    accept_flags |= SOCK_CLOEXEC;
#endif
    int sockfd = accept4(listener->watcher.fd,
                    (struct sockaddr *)&con->client.addr,
                    &con->client.addr_len,
                    accept_flags);
#else
    int sockfd = accept(listener->watcher.fd,
                    (struct sockaddr *)&con->client.addr,
                    &con->client.addr_len);
#endif
    if (sockfd < 0) {
        int saved_errno = errno;

        warn("accept failed: %s", strerror(errno));
        free_connection(con);

        errno = saved_errno;
        return 0;
    }

    if (set_cloexec(sockfd) < 0) {
        int saved_errno = errno;
        warn("fcntl(FD_CLOEXEC) failed on accepted socket: %s", strerror(errno));
        close(sockfd);
        free_connection(con);
        errno = saved_errno;
        return 0;
    }

#ifndef HAVE_ACCEPT4
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    if (!listener_acl_allows(listener, &con->client.addr)) {
        char addrbuf[INET6_ADDRSTRLEN];
        char listener_buf[ADDRESS_BUFFER_SIZE];
        const char *ip = format_sockaddr_ip(&con->client.addr, addrbuf, sizeof(addrbuf));

        info("Connection from %s denied by ACL on %s",
                ip != NULL ? ip : "(unknown)",
                display_address(listener->address, listener_buf, sizeof(listener_buf)));
        close(sockfd);
        free_connection(con);
        return 1;
    }

    ev_tstamp now = ev_now(loop);

    if (!rate_limit_allow_connection(&con->client.addr, now)) {
        char addrbuf[INET6_ADDRSTRLEN];
        const char *ip = format_sockaddr_ip(&con->client.addr, addrbuf, sizeof(addrbuf));

        info("Per-IP connection rate exceeded for %s", ip != NULL ? ip : "(unknown)");
        close(sockfd);
        free_connection(con);
        return 1;
    }

    if (getsockname(sockfd, (struct sockaddr *)&con->client.local_addr,
                &con->client.local_addr_len) != 0) {
        int saved_errno = errno;

        warn("getsockname failed: %s", strerror(errno));
        free_connection(con);

        errno = saved_errno;
        return 0;
    }

    /* Avoiding type-punned pointer warning */
    struct ev_io *client_watcher = &con->client.watcher;
    ev_io_init(client_watcher, connection_cb, sockfd, EV_READ);
    con->client.watcher.data = con;
    con->state = ACCEPTED;
    con->established_timestamp = now;

    TAILQ_INSERT_HEAD(&connections, con, entries);
    connection_account_add();
    start_buffer_shrink_timer(loop);

    ev_io_start(loop, client_watcher);
    reset_idle_timer(con, loop);

    if (con->listener->table->use_proxy_header ||
            con->listener->fallback_use_proxy_header)
        insert_proxy_v1_header(con);

    return 1;
}

/*
 * Close and free all connections
 */
void
free_connections(struct ev_loop *loop) {
    struct Connection *iter;
    while ((iter = TAILQ_FIRST(&connections)) != NULL) {
        TAILQ_REMOVE(&connections, iter, entries);
        connection_account_remove();
        close_connection(iter, loop);
        free_connection(iter);
    }
    stop_buffer_shrink_timer(loop);
}

/* dumps a list of all connections for debugging */
void
print_connections(void) {
    char filename[] = "/tmp/sniproxy-connections-XXXXXX";

    mode_t old_umask = umask(077);
    int fd = mkstemp(filename);
    umask(old_umask);
    if (fd < 0) {
        warn("mkstemp failed: %s", strerror(errno));
        return;
    }

    if (set_cloexec(fd) < 0) {
        warn("set_cloexec failed for %s: %s", filename, strerror(errno));
        close(fd);
        unlink(filename);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        warn("fstat failed for %s: %s", filename, strerror(errno));
        close(fd);
        unlink(filename);
        return;
    }

    mode_t desired_mode = S_IRUSR | S_IWUSR;
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (fchmod(fd, desired_mode) != 0) {
            warn("fchmod failed for %s: %s", filename, strerror(errno));
            close(fd);
            unlink(filename);
            return;
        }
    }

    FILE *temp = fdopen(fd, "w");
    if (temp == NULL) {
        warn("fdopen failed: %s", strerror(errno));
        close(fd);
        unlink(filename);
        return;
    }

    fprintf(temp, "Running connections:\n");
    fprintf(temp, "  active=%zu peak=%zu memory=%zuB peak_memory=%zuB\n\n",
            connections_active_count(), connections_peak_count(),
            connections_memory_usage_bytes(), connections_memory_peak_bytes());
    struct Connection *iter = TAILQ_FIRST(&connections);
    while (iter != NULL) {
        print_connection(temp, iter);
        iter = TAILQ_NEXT(iter, entries);
    }

    if (fclose(temp) < 0) {
        warn("fclose failed: %s", strerror(errno));
        unlink(filename);
        return;
    }

    notice("Dumped connections to %s", filename);
}

/*
 * Test is client socket is open
 *
 * Returns true iff the client socket is opened based on connection state.
 */
static inline int
client_socket_open(const struct Connection *con) {
    return con->state == ACCEPTED ||
        con->state == PARSED ||
        con->state == RESOLVING ||
        con->state == RESOLVED ||
        con->state == CONNECTED ||
        con->state == SERVER_CLOSED;
}

/*
 * Test is server socket is open
 *
 * Returns true iff the server socket is opened based on connection state.
 */
static inline int
server_socket_open(const struct Connection *con) {
    return con->state == CONNECTED ||
        con->state == CLIENT_CLOSED;
}

/*
 * Main client callback: this is used by both the client and server watchers
 *
 * The logic is almost the same except for:
 *  + input buffer
 *  + output buffer
 *  + how to close the socket
 *
 */
static void
connection_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct Connection *con = (struct Connection *)w->data;
    int is_client = &con->client.watcher == w;
    const char *socket_name =
        is_client ? "client" : "server";
    struct Buffer *input_buffer =
        is_client ? con->client.buffer : con->server.buffer;
    struct Buffer *output_buffer =
        is_client ? con->server.buffer : con->client.buffer;
        int client_open = client_socket_open(con);
    int server_open = server_socket_open(con);
    
    /* Receive first in case the socket was closed */
    if (revents & EV_READ && buffer_room(input_buffer) == 0) {
        if (!is_client) {
            if (buffer_reserve(input_buffer, buffer_size(input_buffer)) < 0) {
                char server[INET6_ADDRSTRLEN + 8];

                warn("Response from %s exceeded %zu byte buffer size",
                        display_sockaddr(&con->server.addr,
                            con->server.addr_len,
                            server, sizeof(server)),
                        buffer_size(input_buffer));

                if (is_client) {
                    close_client_socket(con, loop);
                    client_open = 0;
                } else {
                    close_server_socket(con, loop);
                    server_open = 0;
                }
                return;
            }
        }
    }

    if (revents & EV_READ && buffer_room(input_buffer)) {
        ssize_t bytes_received = 0;
        int read_activity = 0;

        do {
            bytes_received = buffer_recv(input_buffer, w->fd, 0, loop);
            if (bytes_received > 0) {
                read_activity = 1;
                continue;
            }

            /*
             * Stop retrying within this callback even when interrupted so
             * other watchers can run. EINTR is treated as a temporary error
             * below.
             */
            break;
        } while (buffer_room(input_buffer));

        if (read_activity)
            reset_idle_timer(con, loop);

        if (bytes_received < 0 && !IS_TEMPORARY_SOCKERR(errno)) {
            warn("recv(%s): %s, closing connection",
                    socket_name,
                    strerror(errno));

            if (is_client) {
                close_client_socket(con, loop);
                client_open = 0;
            } else {
                close_server_socket(con, loop);
                server_open = 0;
            }
            revents = 0; /* Clear revents so we don't try to send */
        } else if (bytes_received == 0) { /* peer closed socket */
            if (is_client) {
                close_client_socket(con, loop);
                client_open = 0;
            } else {
                close_server_socket(con, loop);
                server_open = 0;
            }
            revents = 0;
        }
    }

    /* Transmit */
    if (revents & EV_WRITE && buffer_len(output_buffer)) {
        ssize_t bytes_transmitted = 0;
        int write_activity = 0;

        do {
            bytes_transmitted = buffer_send(output_buffer, w->fd, 0, loop);
            if (bytes_transmitted > 0) {
                write_activity = 1;
                continue;
            }

            /* See comment above for receive side. */
            break;
        } while (buffer_len(output_buffer));

        if (write_activity)
            reset_idle_timer(con, loop);

        if (bytes_transmitted < 0 && !IS_TEMPORARY_SOCKERR(errno)) {
            warn("send(%s): %s, closing connection",
                    socket_name,
                    strerror(errno));

            if (is_client) {
                close_client_socket(con, loop);
                client_open = 0;
            } else {
                close_server_socket(con, loop);
                server_open = 0;
            }
        }
    }

    /* Handle any state specific logic, note we may transition through several
     * states during a single call */
    if (is_client && con->state == ACCEPTED)
        parse_client_request(con);
    if (is_client && con->state == PARSED)
        resolve_server_address(con, loop);
    if (is_client && con->state == RESOLVED) {
        initiate_server_connect(con, loop);
        server_open = server_socket_open(con);
    }

    /* Close other socket if we have flushed corresponding buffer */
    if (con->state == SERVER_CLOSED && buffer_len(con->server.buffer) == 0) {
        close_client_socket(con, loop);
        client_open = 0;
    }
    if (con->state == CLIENT_CLOSED && buffer_len(con->client.buffer) == 0) {
        close_server_socket(con, loop);
        server_open = 0;
    }

    if (con->state == CLOSED) {
        stop_idle_timer(con, loop);
        TAILQ_REMOVE(&connections, con, entries);
        connection_account_remove();

        if (con->listener->access_log)
            log_connection(con);

        free_connection(con);
        maybe_stop_buffer_shrink_timer(loop);
        return;
    }

    reactivate_watchers_with_state(con, loop, client_open, server_open);
}

static void
reactivate_watchers(struct Connection *con, struct ev_loop *loop) {
    reactivate_watchers_with_state(con, loop,
            client_socket_open(con),
            server_socket_open(con));
}

static void
reactivate_watchers_with_state(struct Connection *con, struct ev_loop *loop,
        int client_open, int server_open) {
    struct ev_io *client_watcher = &con->client.watcher;
    struct ev_io *server_watcher = &con->server.watcher;

    /* Reactivate watchers */
    if (client_open)
        reactivate_watcher(loop, client_watcher,
                con->client.buffer, con->server.buffer);

    if (server_open)
        reactivate_watcher(loop, server_watcher,
                con->server.buffer, con->client.buffer);

    /* Neither watcher is active when the corresponding socket is closed */
    assert(client_open || !ev_is_active(client_watcher));
    assert(server_open || !ev_is_active(server_watcher));

    /* At least one watcher is still active for this connection,
     * or DNS callback active */
    assert((ev_is_active(client_watcher) && con->client.watcher.events) ||
           (ev_is_active(server_watcher) && con->server.watcher.events) ||
           con->state == RESOLVING);

}

static void
reactivate_watcher(struct ev_loop *loop, struct ev_io *w,
        const struct Buffer *input_buffer,
        const struct Buffer *output_buffer) {
    int events = 0;

    if (buffer_room(input_buffer))
        events |= EV_READ;

    if (buffer_len(output_buffer))
        events |= EV_WRITE;

    if (ev_is_active(w)) {
        if (events == 0)
            ev_io_stop(loop, w);
        else if (events != w->events) {
            ev_io_stop(loop, w);
            ev_io_set(w, w->fd, events);
            ev_io_start(loop, w);
        }
    } else if (events != 0) {
        ev_io_set(w, w->fd, events);
        ev_io_start(loop, w);
    }
}

static void
reset_idle_timer(struct Connection *con, struct ev_loop *loop) {
    if (CONNECTION_IDLE_TIMEOUT <= 0.0)
        return;

    if (ev_is_active(&con->idle_timer))
        ev_timer_stop(loop, &con->idle_timer);

    ev_timer_set(&con->idle_timer, CONNECTION_IDLE_TIMEOUT, 0.0);
    ev_timer_start(loop, &con->idle_timer);
}

static void
stop_idle_timer(struct Connection *con, struct ev_loop *loop) {
    if (ev_is_active(&con->idle_timer))
        ev_timer_stop(loop, &con->idle_timer);
    else if (ev_is_pending((struct ev_watcher *)&con->idle_timer))
        ev_clear_pending(loop, (struct ev_watcher *)&con->idle_timer);
}

static inline double
rate_limit_bucket_capacity(void) {
    return per_ip_connection_rate_limit <= 1.0 ? 1.0 : per_ip_connection_rate_limit;
}

static void
rate_limit_reset(void) {
    for (size_t i = 0; i < RATE_LIMIT_TABLE_SIZE; i++) {
        struct RateLimitBucket *bucket = rate_limit_table[i];

        while (bucket != NULL) {
            struct RateLimitBucket *next = bucket->next;
            free(bucket);
            bucket = next;
        }

        rate_limit_table[i] = NULL;
    }

    rate_limit_last_cleanup = 0.0;
}

static void
rate_limit_cleanup(ev_tstamp now) {
    if (now - rate_limit_last_cleanup < RATE_LIMIT_CLEANUP_INTERVAL)
        return;

    for (size_t i = 0; i < RATE_LIMIT_TABLE_SIZE; i++) {
        struct RateLimitBucket **current = &rate_limit_table[i];

        while (*current != NULL) {
            struct RateLimitBucket *bucket = *current;

            if (now - bucket->last_check > RATE_LIMIT_IDLE_TTL) {
                *current = bucket->next;
                free(bucket);
            } else {
                current = &bucket->next;
            }
        }
    }

    rate_limit_last_cleanup = now;
}

static uint32_t
hash_sockaddr_ip(const struct sockaddr_storage *addr, uint32_t *out_v4) {
    if (out_v4 != NULL)
        *out_v4 = 0;

    switch (addr->ss_family) {
        case AF_INET: {
            const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
            uint32_t value = ntohl(in->sin_addr.s_addr);
            if (out_v4 != NULL)
                *out_v4 = value;
            value ^= value >> 16;
            return value;
        }
        case AF_INET6: {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
            uint32_t words[4];
            memcpy(words, &in6->sin6_addr, sizeof(words));
            uint32_t value = words[0] ^ words[1] ^ words[2] ^ words[3];
            value ^= in6->sin6_scope_id;
            return value;
        }
        default:
            return 0;
    }
}

static int
sockaddr_equal_ip(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a == b)
        return 1;
    if (a->ss_family != b->ss_family)
        return 0;

    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *in_a = (const struct sockaddr_in *)a;
        const struct sockaddr_in *in_b = (const struct sockaddr_in *)b;
        return memcmp(&in_a->sin_addr, &in_b->sin_addr, sizeof(struct in_addr)) == 0;
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in_a = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *in_b = (const struct sockaddr_in6 *)b;

        if (in_a->sin6_scope_id != in_b->sin6_scope_id)
            return 0;

        return memcmp(&in_a->sin6_addr, &in_b->sin6_addr, sizeof(struct in6_addr)) == 0;
    }

    return 0;
}

static int
rate_limit_allow_connection(const struct sockaddr_storage *addr, ev_tstamp now) {
    if (per_ip_connection_rate_limit <= 0.0)
        return 1;

    if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
        return 1;

    rate_limit_cleanup(now);

    uint32_t addr_v4 = 0;
    uint32_t hash = hash_sockaddr_ip(addr, &addr_v4);
    size_t bucket_index = hash % RATE_LIMIT_TABLE_SIZE;
    struct RateLimitBucket *bucket = rate_limit_table[bucket_index];
    struct RateLimitBucket *prev = NULL;
    double capacity = rate_limit_bucket_capacity();

    while (bucket != NULL) {
        if (bucket->addr_hash == hash) {
            if (addr->ss_family == AF_INET && bucket->addr_v4 == addr_v4)
                break;
            if (addr->ss_family == AF_INET6 && sockaddr_equal_ip(&bucket->addr, addr))
                break;
        }
        prev = bucket;
        bucket = bucket->next;
    }

    if (bucket == NULL) {
        bucket = calloc(1, sizeof(*bucket));
        if (bucket == NULL) {
            err("calloc: %s", strerror(errno));
            return 1;
        }

        bucket->addr = *addr;
        bucket->addr_hash = hash;
        bucket->addr_v4 = addr_v4;
        bucket->last_check = now;
        bucket->allowance = capacity - 1.0;
        bucket->next = rate_limit_table[bucket_index];
        rate_limit_table[bucket_index] = bucket;
        return 1;
    }

    if (prev != NULL) {
        prev->next = bucket->next;
        bucket->next = rate_limit_table[bucket_index];
        rate_limit_table[bucket_index] = bucket;
    }

    double allowance = bucket->allowance;
    allowance += (now - bucket->last_check) * per_ip_connection_rate_limit;
    if (allowance > capacity)
        allowance = capacity;

    bucket->last_check = now;

    if (allowance < 1.0) {
        bucket->allowance = allowance;
        return 0;
    }

    bucket->allowance = allowance - 1.0;
    return 1;
}

static const char *
format_sockaddr_ip(const struct sockaddr_storage *addr, char *buffer, size_t len) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        if (inet_ntop(AF_INET, &in->sin_addr, buffer, len) != NULL)
            return buffer;
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (inet_ntop(AF_INET6, &in6->sin6_addr, buffer, len) != NULL)
            return buffer;
    }

    return NULL;
}

static void
copy_sockaddr_to_storage(struct sockaddr_storage *dst, const void *src, socklen_t len) {
    if (dst == NULL)
        return;

    if (src == NULL || len == 0) {
        memset(dst, 0, sizeof(*dst));
        return;
    }

    if (len == sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)src;
        *(struct sockaddr_in *)dst = *in;
    } else if (len == sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)src;
        *(struct sockaddr_in6 *)dst = *in6;
    } else {
        memcpy(dst, src, len);
    }

    if (len < (socklen_t)sizeof(*dst)) {
        memset((char *)dst + len, 0, sizeof(*dst) - (size_t)len);
    }
}

void
connections_set_per_ip_connection_rate(double rate) {
    if (rate < 0.0)
        rate = 0.0;

    per_ip_connection_rate_limit = rate;
    rate_limit_reset();
}

static size_t max_concurrent_dns_queries = DEFAULT_DNS_QUERY_CONCURRENCY;
static size_t active_dns_queries;

static int
dns_query_acquire(void) {
    if (active_dns_queries >= max_concurrent_dns_queries)
        return 0;

    active_dns_queries++;
    return 1;
}

static void
dns_query_release(void) {
    assert(active_dns_queries > 0);
    active_dns_queries--;
}

void
connections_set_dns_query_limit(size_t limit) {
    if (limit == 0)
        limit = 1;

    max_concurrent_dns_queries = limit;
}

static void
connection_memory_adjust(ssize_t delta) {
    if (delta >= 0) {
        connection_memory_in_use += (size_t)delta;
        if (connection_memory_in_use > connection_memory_peak)
            connection_memory_peak = connection_memory_in_use;
    } else {
        size_t abs_delta = (size_t)(-delta);
        if (abs_delta > connection_memory_in_use)
            connection_memory_in_use = 0;
        else
            connection_memory_in_use -= abs_delta;
    }
}

static void
buffer_memory_observer(ssize_t delta) {
    connection_memory_adjust(delta);
}

static void
connection_account_add(void) {
    connection_active_count++;
    if (connection_active_count > connection_peak_count)
        connection_peak_count = connection_active_count;
}

static void
connection_account_remove(void) {
    if (connection_active_count > 0)
        connection_active_count--;
}

size_t
connections_memory_usage_bytes(void) {
    return connection_memory_in_use;
}

size_t
connections_memory_peak_bytes(void) {
    return connection_memory_peak;
}

size_t
connections_active_count(void) {
    return connection_active_count;
}

size_t
connections_peak_count(void) {
    return connection_peak_count;
}

static void
connection_idle_cb(struct ev_loop *loop, struct ev_timer *w, int revents __attribute__((unused))) {
    struct Connection *con = w->data;
    char client[INET6_ADDRSTRLEN + 8];

    warn("Closing idle connection from %s after %.0f seconds without activity",
            display_sockaddr(&con->client.addr, con->client.addr_len, client, sizeof(client)),
            CONNECTION_IDLE_TIMEOUT);

    close_connection(con, loop);
    TAILQ_REMOVE(&connections, con, entries);
    connection_account_remove();

    if (con->listener->access_log)
        log_connection(con);

    free_connection(con);
    maybe_stop_buffer_shrink_timer(loop);
}

static void
buffer_shrink_timer_cb(struct ev_loop *loop, struct ev_timer *w __attribute__((unused)),
        int revents __attribute__((unused))) {
    if (TAILQ_EMPTY(&connections))
        return;

    ev_tstamp now = ev_now(loop);
    struct Connection *con;
    TAILQ_FOREACH(con, &connections, entries) {
        buffer_maybe_shrink_idle(con->server.buffer, now, BUFFER_SHRINK_IDLE_SECONDS);
        buffer_maybe_shrink_idle(con->client.buffer, now, BUFFER_SHRINK_IDLE_SECONDS);
    }
}

static void
start_buffer_shrink_timer(struct ev_loop *loop) {
    if (!buffer_shrink_timer_configured || BUFFER_SHRINK_IDLE_SECONDS <= 0.0)
        return;

    if (buffer_shrink_loop == NULL)
        buffer_shrink_loop = loop;

    assert(buffer_shrink_loop == loop);

    if (!ev_is_active(&buffer_shrink_timer))
        ev_timer_start(loop, &buffer_shrink_timer);
}

static void
stop_buffer_shrink_timer(struct ev_loop *loop __attribute__((unused))) {
    if (!buffer_shrink_timer_configured || BUFFER_SHRINK_IDLE_SECONDS <= 0.0)
        return;

    if (buffer_shrink_loop == NULL)
        return;

    struct ev_loop *active_loop = buffer_shrink_loop;

    if (ev_is_active(&buffer_shrink_timer))
        ev_timer_stop(active_loop, &buffer_shrink_timer);
    else if (ev_is_pending((struct ev_watcher *)&buffer_shrink_timer))
        ev_clear_pending(active_loop, (struct ev_watcher *)&buffer_shrink_timer);

    buffer_shrink_loop = NULL;
}

static void
maybe_stop_buffer_shrink_timer(struct ev_loop *loop) {
    if (TAILQ_EMPTY(&connections))
        stop_buffer_shrink_timer(loop);
}

static void
insert_proxy_v1_header(struct Connection *con) {
    char header[256];
    size_t len;

    switch (con->client.addr.ss_family) {
        case AF_INET: {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            const struct sockaddr_in *src =
                    (const struct sockaddr_in *)&con->client.addr;
            const struct sockaddr_in *dst =
                    (const struct sockaddr_in *)&con->client.local_addr;

            if (inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip)) == NULL ||
                    inet_ntop(AF_INET, &dst->sin_addr, dst_ip, sizeof(dst_ip)) == NULL)
                goto unknown;

            int n = snprintf(header, sizeof(header),
                    "PROXY TCP4 %s %s %u %u\r\n",
                    src_ip, dst_ip, ntohs(src->sin_port), ntohs(dst->sin_port));
            if (n <= 0 || (size_t)n >= sizeof(header))
                goto unknown;

            len = (size_t)n;
            con->header_len += buffer_push(con->client.buffer, header, len);
            return;
        }
        case AF_INET6: {
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            const struct sockaddr_in6 *src =
                    (const struct sockaddr_in6 *)&con->client.addr;
            const struct sockaddr_in6 *dst =
                    (const struct sockaddr_in6 *)&con->client.local_addr;

            if (inet_ntop(AF_INET6, &src->sin6_addr, src_ip, sizeof(src_ip)) == NULL ||
                    inet_ntop(AF_INET6, &dst->sin6_addr, dst_ip, sizeof(dst_ip)) == NULL)
                goto unknown;

            int n = snprintf(header, sizeof(header),
                    "PROXY TCP6 %s %s %u %u\r\n",
                    src_ip, dst_ip, ntohs(src->sin6_port), ntohs(dst->sin6_port));
            if (n <= 0 || (size_t)n >= sizeof(header))
                goto unknown;

            len = (size_t)n;
            con->header_len += buffer_push(con->client.buffer, header, len);
            return;
        }
        default:
            break;
    }

unknown:
    con->header_len += buffer_push(con->client.buffer,
            "PROXY UNKNOWN\r\n", sizeof("PROXY UNKNOWN\r\n") - 1);
}

static void
parse_client_request(struct Connection *con) {
    const char *payload;
    size_t payload_len = buffer_coalesce(con->client.buffer, (const void **)&payload);
    char *hostname = NULL;

    /* Avoid payload_len underflow and empty request */
    if (payload_len <= con->header_len)
        return;

    payload += con->header_len;
    payload_len -= con->header_len;

    int result = con->listener->protocol->parse_packet(payload, payload_len, &hostname);
    if (result < 0) {
        char client[INET6_ADDRSTRLEN + 8];
        int fatal_parse_error = 0;

        if (result == -1) { /* incomplete request */
            if (buffer_room(con->client.buffer) > 0)
                return; /* give client a chance to send more data */

            if (buffer_reserve(con->client.buffer,
                               buffer_size(con->client.buffer)) == 0)
                return; /* buffer successfully expanded */

            warn("Request from %s exceeded %zu byte buffer size",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_size(con->client.buffer));
        } else if (result == TLS_ERR_CLIENT_RENEGOTIATION) {
            warn("Client from %s attempted TLS renegotiation, rejecting",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)));
        } else if (result == TLS_ERR_UNSUPPORTED_CLIENT_HELLO) {
            warn("Client from %s sent a ClientHello version that cannot carry SNI, rejecting",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)));
            fatal_parse_error = 1;
        } else if (result == -2) {
            warn("Request from %s did not include a hostname",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)));
        } else {
            warn("Unable to parse request from %s: parse_packet returned %d",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    result);

            if (con->listener->log_bad_requests)
                log_bad_request(con, payload, payload_len, result);
        }

        if (hostname != NULL) {
            free(hostname);
            hostname = NULL;
        }

        if (fatal_parse_error || con->listener->fallback_address == NULL) {
            abort_connection(con);
            return;
        }

        /* Parsing failed but a fallback backend is configured. Treat this as a
         * request without a usable hostname so downstream lookups do not see a
         * bogus length derived from the negative parser return value. */
        result = 0;
    }

    con->hostname = hostname;
    con->hostname_len = (size_t)result;
    con->state = PARSED;
}

static void
abort_connection(struct Connection *con) {
    assert(client_socket_open(con));

    buffer_push(con->server.buffer,
            con->listener->protocol->abort_message,
            con->listener->protocol->abort_message_len);

    con->state = SERVER_CLOSED;
}

static void
resolve_server_address(struct Connection *con, struct ev_loop *loop) {
    struct LookupResult result =
        listener_lookup_server_address(con->listener, con->hostname, con->hostname_len);

    if (result.address == NULL) {
        abort_connection(con);
        return;
    } else if (address_is_hostname(result.address)) {
        struct resolv_cb_data *cb_data = malloc(sizeof(struct resolv_cb_data));
        if (cb_data == NULL) {
            err("%s: malloc", __func__);

            if (result.caller_free_address)
                free((void *)result.address);

            abort_connection(con);
            return;
        }
        cb_data->connection = con;
        cb_data->address = result.address;
        cb_data->cb_free_addr = result.caller_free_address;
        cb_data->loop = loop;
        con->use_proxy_header = result.use_proxy_header;

        const char *hostname = address_hostname(result.address);
        if (hostname == NULL || hostname[0] == '\0') {
            err("%s: hostname lookup returned empty result", __func__);

            if (result.caller_free_address)
                free((void *)result.address);

            free(cb_data);

            abort_connection(con);
            reactivate_watchers(con, loop);

            return;
        }

        char hostname_buf[ADDRESS_BUFFER_SIZE];
        snprintf(hostname_buf, sizeof(hostname_buf), "%s", hostname);

        int resolv_mode = RESOLV_MODE_DEFAULT;
        if (con->listener->transparent_proxy) {
            char listener_address[ADDRESS_BUFFER_SIZE];
            switch (con->client.addr.ss_family) {
                case AF_INET:
                    resolv_mode = RESOLV_MODE_IPV4_ONLY;
                    break;
                case AF_INET6:
                    resolv_mode = RESOLV_MODE_IPV6_ONLY;
                    break;
                default:
                    warn("attempt to use transparent proxy with hostname %s "
                            "on non-IP listener %s, falling back to "
                            "non-transparent mode",
                            address_hostname(result.address),
                            display_address(con->listener->address,
                                    listener_address, sizeof(listener_address))
                            );
            }
        }

        if (!dns_query_acquire()) {
            char client[INET6_ADDRSTRLEN + 8];

            notice("Maximum concurrent DNS queries (%zu) reached for %s, closing connection",
                    max_concurrent_dns_queries,
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)));

            if (result.caller_free_address)
                free((void *)result.address);
            free(cb_data);

            abort_connection(con);
            reactivate_watchers(con, loop);

            return;
        }

        con->dns_query_acquired = 1;
        con->state = RESOLVING;
        con->query_handle = resolv_query(hostname,
                resolv_mode, resolv_cb,
                (void (*)(void *))free_resolv_cb_data, cb_data);

        if (con->query_handle == NULL) {
            if (con->dns_query_acquired) {
                dns_query_release();
                con->dns_query_acquired = 0;
            }
            if (con->state == RESOLVING) {
                notice("unable to resolve %s, closing connection", hostname_buf);

                abort_connection(con);
                reactivate_watchers(con, loop);
            }

            con->query_handle = NULL;

            return;
        }
    } else if (address_is_sockaddr(result.address)) {
        con->server.addr_len = address_sa_len(result.address);
        assert(con->server.addr_len <= sizeof(con->server.addr));
        copy_sockaddr_to_storage(&con->server.addr,
                address_sa(result.address),
                (socklen_t)con->server.addr_len);
        con->use_proxy_header = result.use_proxy_header;

        if (result.caller_free_address)
            free((void *)result.address);

        con->state = RESOLVED;
    } else {
        /* invalid address type */
        assert(0);
    }
}

static void
resolv_cb(struct Address *result, void *data) {
    struct resolv_cb_data *cb_data = (struct resolv_cb_data *)data;
    struct Connection *con = cb_data->connection;
    struct ev_loop *loop = cb_data->loop;

    if (con->dns_query_acquired) {
        dns_query_release();
        con->dns_query_acquired = 0;
    }

    if (con->state != RESOLVING) {
        warn("resolv_cb() called for connection not in RESOLVING state");
        return;
    }

    if (result == NULL) {
        notice("unable to resolve %s, closing connection",
                address_hostname(cb_data->address));
        abort_connection(con);
    } else {
        assert(address_is_sockaddr(result));

        /* copy port from server_address */
        address_set_port(result, address_port(cb_data->address));

        con->server.addr_len = address_sa_len(result);
        assert(con->server.addr_len <= sizeof(con->server.addr));
        copy_sockaddr_to_storage(&con->server.addr, address_sa(result),
                (socklen_t)con->server.addr_len);

        con->state = RESOLVED;

        initiate_server_connect(con, loop);
    }

    con->query_handle = NULL;
    reactivate_watchers(con, loop);
}

static void
free_resolv_cb_data(struct resolv_cb_data *cb_data) {
    if (cb_data->cb_free_addr)
        free((void *)cb_data->address);
    free(cb_data);
}

static void
initiate_server_connect(struct Connection *con, struct ev_loop *loop) {
    int socket_type = SOCK_STREAM;
#ifdef HAVE_ACCEPT4
    socket_type |= SOCK_NONBLOCK;
#endif
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif
    int sockfd = socket(con->server.addr.ss_family, socket_type, 0);
    if (sockfd < 0) {
        char client[INET6_ADDRSTRLEN + 8];
        warn("socket failed: %s, closing connection from %s",
                strerror(errno),
                display_sockaddr(&con->client.addr,
                    con->client.addr_len,
                    client, sizeof(client)));
        abort_connection(con);
        return;
    }

    if (set_cloexec(sockfd) < 0) {
        char client[INET6_ADDRSTRLEN + 8];
        warn("fcntl(FD_CLOEXEC) failed on server socket: %s, closing connection from %s",
                strerror(errno),
                display_sockaddr(&con->client.addr,
                    con->client.addr_len,
                    client, sizeof(client)));
        close(sockfd);
        abort_connection(con);
        return;
    }

#ifndef HAVE_ACCEPT4
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    if (con->listener->transparent_proxy &&
            con->client.addr.ss_family == con->server.addr.ss_family) {
#ifdef IP_TRANSPARENT
        int on = 1;
        int result = setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
#else
        int result = -EPERM;
        /* XXX error: not implemented would be better, but this shouldn't be
         * reached since it is prohibited in the configuration parser. */
#endif
        if (result < 0) {
            err("setsockopt IP_TRANSPARENT failed: %s", strerror(errno));
            close(sockfd);
            abort_connection(con);
            return;
        }

        result = bind(sockfd, (struct sockaddr *)&con->client.addr,
                con->client.addr_len);
        if (result < 0) {
            err("bind failed: %s", strerror(errno));
            close(sockfd);
            abort_connection(con);
            return;
        }
    } else if (con->listener->source_address) {
        int on = 1;
        int result = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (result < 0) {
            err("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
            close(sockfd);
            abort_connection(con);
            return;
        }

        int tries = 5;
        do {
            result = bind(sockfd,
                    address_sa(con->listener->source_address),
                    address_sa_len(con->listener->source_address));
        } while (tries-- > 0
                && result < 0
                && errno == EADDRINUSE
                && address_port(con->listener->source_address) == 0);
        if (result < 0) {
            err("bind failed: %s", strerror(errno));
            close(sockfd);
            abort_connection(con);
            return;
        }
    }

    int result = connect(sockfd,
            (struct sockaddr *)&con->server.addr,
            con->server.addr_len);
    /* TODO retry connect in EADDRNOTAVAIL case */
    if (result < 0 && errno != EINPROGRESS) {
        close(sockfd);
        char server[INET6_ADDRSTRLEN + 8];
        warn("Failed to open connection to %s: %s",
                display_sockaddr(&con->server.addr,
                    con->server.addr_len,
                    server, sizeof(server)),
                strerror(errno));
        abort_connection(con);
        return;
    }

    if (getsockname(sockfd, (struct sockaddr *)&con->server.local_addr,
                &con->server.local_addr_len) != 0) {
        close(sockfd);
        warn("getsockname failed: %s", strerror(errno));

        abort_connection(con);
        return;
    }

    if (con->header_len && !con->use_proxy_header) {
        /* If we prepended the PROXY header and this backend isn't configured
         * to receive it, consume it now */
        buffer_pop(con->client.buffer, NULL, con->header_len);
    }

    struct ev_io *server_watcher = &con->server.watcher;
    ev_io_init(server_watcher, connection_cb, sockfd, EV_WRITE);
    con->server.watcher.data = con;
    con->state = CONNECTED;

    ev_io_start(loop, server_watcher);
}

/* Close client socket.
 * Caller must ensure that it has not been closed before.
 */
static void
close_client_socket(struct Connection *con, struct ev_loop *loop) {
    assert(con->state != CLOSED
            && con->state != CLIENT_CLOSED);

    ev_io_stop(loop, &con->client.watcher);

    if (close(con->client.watcher.fd) < 0)
        warn("close failed: %s", strerror(errno));

    if (con->state == RESOLVING) {
        if (con->query_handle != NULL) {
            resolv_cancel(con->query_handle);
            dns_query_release();
            con->dns_query_acquired = 0;
        }
        con->query_handle = NULL;
        con->state = PARSED;
    }

    /* next state depends on previous state */
    if (con->state == SERVER_CLOSED
            || con->state == ACCEPTED
            || con->state == PARSED
            || con->state == RESOLVING
            || con->state == RESOLVED)
        con->state = CLOSED;
    else
        con->state = CLIENT_CLOSED;
}

/* Close server socket.
 * Caller must ensure that it has not been closed before.
 */
static void
close_server_socket(struct Connection *con, struct ev_loop *loop) {
    assert(con->state != CLOSED
            && con->state != SERVER_CLOSED);

    ev_io_stop(loop, &con->server.watcher);

    if (close(con->server.watcher.fd) < 0)
        warn("close failed: %s", strerror(errno));

    /* next state depends on previous state */
    if (con->state == CLIENT_CLOSED)
        con->state = CLOSED;
    else
        con->state = SERVER_CLOSED;
}

static void
close_connection(struct Connection *con, struct ev_loop *loop) {
    assert(con->state != NEW); /* only used during initialization */

    stop_idle_timer(con, loop);

    if (server_socket_open(con))
        close_server_socket(con, loop);

    assert(con->state == ACCEPTED
            || con->state == PARSED
            || con->state == RESOLVING
            || con->state == RESOLVED
            || con->state == SERVER_CLOSED
            || con->state == CLOSED);

    if (client_socket_open(con))
        close_client_socket(con, loop);

    assert(con->state == CLOSED);
}

/*
 * Allocate and initialize a new connection
 */
static struct Connection *
new_connection(struct ev_loop *loop) {
    struct Connection *con = calloc(1, sizeof(struct Connection));
    if (con == NULL)
        return NULL;

    connection_memory_adjust((ssize_t)sizeof(struct Connection));

    con->state = NEW;
    con->client.addr_len = sizeof(con->client.addr);
    con->client.local_addr = (struct sockaddr_storage){.ss_family = AF_UNSPEC};
    con->client.local_addr_len = sizeof(con->client.local_addr);
    con->server.addr_len = sizeof(con->server.addr);
    con->server.local_addr = (struct sockaddr_storage){.ss_family = AF_UNSPEC};
    con->server.local_addr_len = sizeof(con->server.local_addr);
    con->hostname = NULL;
    con->hostname_len = 0;
    con->header_len = 0;
    con->query_handle = NULL;
    con->use_proxy_header = 0;
    ev_timer_init(&con->idle_timer, connection_idle_cb, 0.0, 0.0);
    con->idle_timer.data = con;

    con->client.buffer = new_buffer(CLIENT_BUFFER_INITIAL_SIZE, loop);
    if (con->client.buffer == NULL) {
        free_connection(con);
        return NULL;
    }
    buffer_set_max_size(con->client.buffer, CLIENT_BUFFER_MAX_SIZE);
    con->client.buffer->min_size = CLIENT_BUFFER_MIN_SIZE;

    con->server.buffer = new_buffer(SERVER_BUFFER_INITIAL_SIZE, loop);
    if (con->server.buffer == NULL) {
        free_connection(con);
        return NULL;
    }

    buffer_set_max_size(con->server.buffer, SERVER_BUFFER_MAX_SIZE);
    con->server.buffer->min_size = SERVER_BUFFER_MIN_SIZE;

    return con;
}

static void
log_connection(struct Connection *con) {
    ev_tstamp duration = MAX(con->client.buffer->last_recv,
                             con->server.buffer->last_recv) -
                         con->established_timestamp;
    char client_address[ADDRESS_BUFFER_SIZE];
    char listener_address[ADDRESS_BUFFER_SIZE];
    char server_address[ADDRESS_BUFFER_SIZE];


    display_sockaddr(&con->client.addr, con->client.addr_len,
            client_address, sizeof(client_address));
    display_sockaddr(&con->client.local_addr, con->client.local_addr_len,
            listener_address, sizeof(listener_address));
    display_sockaddr(&con->server.addr, con->server.addr_len,
            server_address, sizeof(server_address));

    const char *logged_hostname = con->hostname != NULL ? con->hostname : "-";
    size_t raw_hostname_len = con->hostname != NULL ? con->hostname_len : 1;
    int hostname_len = raw_hostname_len > (size_t)INT_MAX ? INT_MAX :
            (int)raw_hostname_len;

    log_msg(con->listener->access_log,
           LOG_NOTICE,
           "%s -> %s -> %s [%.*s] %zu/%zu bytes tx %zu/%zu bytes rx %1.3f seconds",
           client_address,
           listener_address,
           server_address,
           hostname_len,
           logged_hostname,
           con->server.buffer->tx_bytes,
           con->server.buffer->rx_bytes,
           con->client.buffer->tx_bytes,
           con->client.buffer->rx_bytes,
           duration);
}

static void
log_bad_request(struct Connection *con __attribute__((unused)), const char *req, size_t req_len, int parse_result) {
    if (req == NULL)
        return;

    debug("parse_packet([redacted], %zu, ...) = %d", req_len, parse_result);
}

/*
 * Free a connection and associated data
 *
 * Requires that no watchers remain active
 */
static void
free_connection(struct Connection *con) {
    if (con == NULL)
        return;

    listener_ref_put(con->listener);
    free_buffer(con->client.buffer);
    free_buffer(con->server.buffer);
    free((void *)con->hostname); /* cast away const'ness */
    connection_memory_adjust(-(ssize_t)sizeof(struct Connection));
    free(con);
}

static void
print_connection(FILE *file, const struct Connection *con) {
    char client[INET6_ADDRSTRLEN + 8];
    char server[INET6_ADDRSTRLEN + 8];

    switch (con->state) {
        case NEW:
            fprintf(file, "NEW           -\t-\n");
            break;
        case ACCEPTED:
            fprintf(file, "ACCEPTED      %s %zu/%zu\t-\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer));
            break;
        case PARSED:
            fprintf(file, "PARSED        %s %zu/%zu\t-\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer));
            break;
        case RESOLVING:
            fprintf(file, "RESOLVING      %s %zu/%zu\t-\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer));
            break;
        case RESOLVED:
            fprintf(file, "RESOLVED      %s %zu/%zu\t-\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer));
            break;
        case CONNECTED:
            fprintf(file, "CONNECTED     %s %zu/%zu\t%s %zu/%zu\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer),
                    display_sockaddr(&con->server.addr,
                        con->server.addr_len,
                        server, sizeof(server)),
                    buffer_len(con->server.buffer), buffer_size(con->server.buffer));
            break;
        case SERVER_CLOSED:
            fprintf(file, "SERVER_CLOSED %s %zu/%zu\t-\n",
                    display_sockaddr(&con->client.addr,
                        con->client.addr_len,
                        client, sizeof(client)),
                    buffer_len(con->client.buffer), buffer_size(con->client.buffer));
            break;
        case CLIENT_CLOSED:
            fprintf(file, "CLIENT_CLOSED -\t%s %zu/%zu\n",
                    display_sockaddr(&con->server.addr,
                        con->server.addr_len,
                        server, sizeof(server)),
                    buffer_len(con->server.buffer), buffer_size(con->server.buffer));
            break;
        case CLOSED:
            fprintf(file, "CLOSED        -\t-\n");
            break;
    }
}
