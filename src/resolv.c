/*
 * Copyright (c) 2014, Dustin Lundquist <dustin@null-ptr.net>
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/wait.h>
#include <ev.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#ifdef HAVE_LIBUDNS
#include <udns.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "resolv.h"
#include "address.h"
#include "logger.h"
#include "fd_util.h"

#ifndef HAVE_LIBUDNS
/*
 * If we do not have a DNS resolution library stub out module as no ops
 */

int
resolv_init(struct ev_loop *loop, char **nameservers, char **search_domains,
        int mode) {
    (void)loop;
    (void)nameservers;
    (void)search_domains;
    (void)mode;

    return 0;
}

void
resolv_shutdown(struct ev_loop *loop) {
    (void)loop;
}

struct ResolvQuery *
resolv_query(const char *hostname, int mode,
        void (*client_cb)(struct Address *, void *),
        void (*client_free_cb)(void *), void *client_cb_data) {
    (void)hostname;
    (void)mode;
    (void)client_cb;
    (void)client_free_cb;
    (void)client_cb_data;

    return NULL;
}

void
resolv_cancel(struct ResolvQuery *query_handle) {
    (void)query_handle;
}

#else
/*
 * Implement DNS resolution interface using a dedicated resolver child process
 */

#define RESOLVER_CMD_QUERY      1u
#define RESOLVER_CMD_CANCEL     2u
#define RESOLVER_CMD_RESULT     3u
#define RESOLVER_CMD_SHUTDOWN   4u

#define RESOLVER_MAX_HOSTNAME_LEN    1023
#define RESOLVER_IPC_MAX_PAYLOAD     4096
#define RESOLVER_MAX_ADDR_LEN        ((size_t)sizeof(struct sockaddr_storage))

struct resolver_ipc_header {
    uint32_t type;
    uint32_t id;
    uint32_t payload_len;
};

struct ResolvQuery {
    uint32_t id;
    int resolv_mode;
    void (*client_cb)(struct Address *, void *);
    void (*client_free_cb)(void *);
    void *client_cb_data;
    struct ResolvQuery *next;
};

static int resolver_sock = -1;
static pid_t resolver_pid = -1;
static uint32_t resolver_next_query_id = 1;
static struct ResolvQuery *resolver_queries = NULL;
static pthread_mutex_t resolver_queries_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ev_io resolver_ipc_watcher;
static int default_resolv_mode = RESOLV_MODE_IPV4_ONLY;

/* Parent-side helpers */
static int resolver_send_message(uint32_t type, uint32_t id,
        const void *payload, size_t payload_len);
static void resolver_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void resolver_process_datagram(const uint8_t *buffer, ssize_t len);
static void resolver_handle_result(uint32_t id, const uint8_t *payload, size_t payload_len);
static void resolver_attach_query(struct ResolvQuery *query);
static struct ResolvQuery *resolver_take_query(uint32_t id);
static int resolver_detach_query(struct ResolvQuery *query);
static void resolver_cleanup_pending_queries(void);

/* Child-side declarations */
struct ResolverChildQuery;

static void resolver_child_main(int sockfd, char **nameservers,
        char **search_domains, int default_mode) __attribute__((noreturn));
static void resolver_child_setup_dns(struct ev_loop *loop, char **nameservers,
        char **search_domains, int default_mode);
static void resolver_child_shutdown_dns(struct ev_loop *loop);
static void resolver_child_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void resolver_child_submit_query(uint32_t id, int mode,
        const char *hostname, size_t hostname_len);
static void resolver_child_cancel_query(uint32_t id);
static void resolver_child_send_result(uint32_t id, const struct Address *address, int status);
static void resolver_child_cancel_all(void);
static struct ResolverChildQuery *resolver_child_find_query(uint32_t id);
static void resolver_child_remove_query(struct ResolverChildQuery *query);
static void resolver_child_free_query(struct ResolverChildQuery *query);
static void resolver_child_dns_sock_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void resolver_child_dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
static void resolver_child_dns_timer_setup_cb(struct dns_ctx *ctx, int timeout, void *data);
static void resolver_child_process_callback(struct ResolverChildQuery *query);
static inline int resolver_child_all_queries_are_null(struct ResolverChildQuery *query);
static inline void resolver_child_cancel_outstanding_queries(struct ResolverChildQuery *query);
static void resolver_child_maybe_process_callback(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_ipv4_first(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_ipv6_first(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_any(struct ResolverChildQuery *query);
static void resolver_child_dns_query_v4_cb(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data);
static void resolver_child_dns_query_v6_cb(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data);

static int child_default_resolv_mode = RESOLV_MODE_IPV4_ONLY;
static int child_sock = -1;
static int child_dns_sock = -1;
static struct ev_loop *child_loop = NULL;
static struct ResolverChildQuery *child_queries = NULL;
static struct dns_ctx *child_dns_ctx = NULL;
static struct ev_io child_ipc_watcher;
static struct ev_io child_dns_io_watcher;
static struct ev_timer child_dns_timeout_watcher;

struct ResolverChildQuery {
    uint32_t id;
    int resolv_mode;
    struct dns_query *queries[2];
    size_t response_count;
    struct Address **responses;
    size_t ipv4_response_count;
    size_t ipv6_response_count;
    int callback_completed;
    char *hostname;
    struct ResolverChildQuery *next;
};

int
resolv_init(struct ev_loop *loop, char **nameservers, char **search, int mode) {
    int sockets[2];
    int socket_type = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    socket_type |= SOCK_NONBLOCK;
#endif

    if (socketpair(AF_UNIX, socket_type, 0, sockets) < 0)
        fatal("resolver socketpair failed: %s", strerror(errno));

#ifndef SOCK_CLOEXEC
    if (set_cloexec(sockets[0]) < 0 || set_cloexec(sockets[1]) < 0)
        fatal("Failed to set close-on-exec on resolver socket: %s",
                strerror(errno));
#endif

#ifndef SOCK_NONBLOCK
    int flags = fcntl(sockets[0], F_GETFL, 0);
    if (flags >= 0)
        fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockets[1], F_GETFL, 0);
    if (flags >= 0)
        fcntl(sockets[1], F_SETFL, flags | O_NONBLOCK);
#endif

    pid_t pid = fork();
    if (pid < 0) {
        fatal("resolver fork failed: %s", strerror(errno));
    } else if (pid == 0) {
        close(sockets[0]);
        resolver_child_main(sockets[1], nameservers, search, mode);
    }

    close(sockets[1]);

    resolver_sock = sockets[0];
    resolver_pid = pid;
    default_resolv_mode = mode;

    ev_io_init(&resolver_ipc_watcher, resolver_ipc_cb, resolver_sock, EV_READ);
    ev_io_start(loop, &resolver_ipc_watcher);

    return resolver_sock;
}

void
resolv_shutdown(struct ev_loop *loop) {
    if (resolver_sock >= 0) {
        ev_io_stop(loop, &resolver_ipc_watcher);
        resolver_send_message(RESOLVER_CMD_SHUTDOWN, 0, NULL, 0);
        close(resolver_sock);
        resolver_sock = -1;
    }

    if (resolver_pid > 0) {
        int status;
        if (waitpid(resolver_pid, &status, 0) < 0)
            err("waitpid on resolver failed: %s", strerror(errno));
        resolver_pid = -1;
    }

    resolver_cleanup_pending_queries();
}

struct ResolvQuery *
resolv_query(const char *hostname, int mode,
        void (*client_cb)(struct Address *, void *),
        void (*client_free_cb)(void *), void *client_cb_data) {
    if (resolver_sock < 0 || hostname == NULL) {
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }

    size_t hostname_len = strlen(hostname);
    if (hostname_len == 0 || hostname_len > RESOLVER_MAX_HOSTNAME_LEN) {
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }

    struct ResolvQuery *query = calloc(1, sizeof(*query));
    if (query == NULL) {
        err("Failed to allocate memory for DNS query callback data.");
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }

    query->id = resolver_next_query_id++;
    query->resolv_mode = mode != RESOLV_MODE_DEFAULT ?
            mode : default_resolv_mode;
    query->client_cb = client_cb;
    query->client_free_cb = client_free_cb;
    query->client_cb_data = client_cb_data;
    resolver_attach_query(query);

    uint8_t payload[sizeof(uint32_t) + RESOLVER_MAX_HOSTNAME_LEN];
    uint32_t mode_net = htonl((uint32_t)query->resolv_mode);
    memcpy(payload, &mode_net, sizeof(mode_net));
    memcpy(payload + sizeof(mode_net), hostname, hostname_len);

    if (resolver_send_message(RESOLVER_CMD_QUERY, query->id,
            payload, sizeof(mode_net) + hostname_len) < 0) {
        resolver_detach_query(query);
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        free(query);
        return NULL;
    }

    return query;
}

void
resolv_cancel(struct ResolvQuery *query) {
    if (query == NULL)
        return;

    if (!resolver_detach_query(query))
        return;

    resolver_send_message(RESOLVER_CMD_CANCEL, query->id, NULL, 0);

    if (query->client_free_cb != NULL)
        query->client_free_cb(query->client_cb_data);

    free(query);
}

static int
resolver_send_message(uint32_t type, uint32_t id, const void *payload, size_t payload_len) {
    if (resolver_sock < 0)
        return -1;

    if (payload_len > RESOLVER_IPC_MAX_PAYLOAD) {
        err("resolver payload too large: %zu", payload_len);
        return -1;
    }

    uint8_t buffer[sizeof(struct resolver_ipc_header) + RESOLVER_IPC_MAX_PAYLOAD];
    struct resolver_ipc_header header;

    header.type = htonl(type);
    header.id = htonl(id);
    header.payload_len = htonl((uint32_t)payload_len);

    memcpy(buffer, &header, sizeof(header));
    if (payload_len > 0 && payload != NULL)
        memcpy(buffer + sizeof(header), payload, payload_len);

    ssize_t written = send(resolver_sock, buffer, sizeof(header) + payload_len, 0);
    if (written < 0) {
        err("resolver send failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static void
resolver_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    if (!(revents & EV_READ))
        return;

    for (;;) {
        uint8_t buffer[sizeof(struct resolver_ipc_header) + RESOLVER_IPC_MAX_PAYLOAD];
        ssize_t len = recv(w->fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;

            err("resolver recv failed: %s", strerror(errno));
            break;
        }

        if (len == 0) {
            warn("resolver socket closed");
            ev_io_stop(loop, w);
            if (resolver_sock >= 0) {
                close(resolver_sock);
                resolver_sock = -1;
            }
            break;
        }

        resolver_process_datagram(buffer, len);
    }
}

static void
resolver_process_datagram(const uint8_t *buffer, ssize_t len) {
    if (len < (ssize_t)sizeof(struct resolver_ipc_header))
        return;

    struct resolver_ipc_header header;
    memcpy(&header, buffer, sizeof(header));

    uint32_t type = ntohl(header.type);
    uint32_t id = ntohl(header.id);
    uint32_t payload_len = ntohl(header.payload_len);

    if (payload_len > RESOLVER_IPC_MAX_PAYLOAD)
        return;

    if ((ssize_t)payload_len != len - (ssize_t)sizeof(header))
        return;

    const uint8_t *payload = buffer + sizeof(header);

    switch (type) {
        case RESOLVER_CMD_RESULT:
            resolver_handle_result(id, payload, payload_len);
            break;
        default:
            break;
    }
}

static void
resolver_handle_result(uint32_t id, const uint8_t *payload, size_t payload_len) {
    struct ResolvQuery *query = resolver_take_query(id);
    if (query == NULL)
        return;

    int32_t status = -1;
    struct Address *address = NULL;

    if (payload_len >= sizeof(uint32_t) * 2) {
        uint32_t status_net;
        memcpy(&status_net, payload, sizeof(uint32_t));
        status = (int32_t)ntohl(status_net);

        uint32_t addr_len_net;
        memcpy(&addr_len_net, payload + sizeof(uint32_t), sizeof(uint32_t));
        uint32_t addr_len = ntohl(addr_len_net);

        if (status == 0) {
            if (addr_len == 0 || payload_len != sizeof(uint32_t) * 2 + addr_len) {
                status = -1;
            } else if (addr_len > RESOLVER_MAX_ADDR_LEN) {
                status = -1;
            } else {
                struct sockaddr_storage storage;
                memset(&storage, 0, sizeof(storage));
                memcpy(&storage, payload + sizeof(uint32_t) * 2, addr_len);
                address = new_address_sa((struct sockaddr *)&storage, (socklen_t)addr_len);
                if (address == NULL)
                    status = -1;
            }
        }
    }

    if (status != 0 && address != NULL) {
        free(address);
        address = NULL;
    }

    if (query->client_cb != NULL)
        query->client_cb((status == 0) ? address : NULL, query->client_cb_data);

    if (address != NULL)
        free(address);

    if (query->client_free_cb != NULL)
        query->client_free_cb(query->client_cb_data);

    free(query);
}

static void
resolver_attach_query(struct ResolvQuery *query) {
    if (query == NULL)
        return;

    pthread_mutex_lock(&resolver_queries_lock);
    query->next = resolver_queries;
    resolver_queries = query;
    pthread_mutex_unlock(&resolver_queries_lock);
}

static struct ResolvQuery *
resolver_take_query(uint32_t id) {
    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolvQuery **iter = &resolver_queries;
    while (*iter != NULL) {
        if ((*iter)->id == id) {
            struct ResolvQuery *found = *iter;
            *iter = found->next;
            found->next = NULL;
            pthread_mutex_unlock(&resolver_queries_lock);
            return found;
        }
        iter = &(*iter)->next;
    }
    pthread_mutex_unlock(&resolver_queries_lock);
    return NULL;
}

static int
resolver_detach_query(struct ResolvQuery *query) {
    if (query == NULL)
        return 0;

    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolvQuery **iter = &resolver_queries;
    while (*iter != NULL) {
        if (*iter == query) {
            *iter = query->next;
            query->next = NULL;
            pthread_mutex_unlock(&resolver_queries_lock);
            return 1;
        }
        iter = &(*iter)->next;
    }
    pthread_mutex_unlock(&resolver_queries_lock);
    return 0;
}

static void
resolver_cleanup_pending_queries(void) {
    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolvQuery *iter = resolver_queries;
    resolver_queries = NULL;
    pthread_mutex_unlock(&resolver_queries_lock);

    while (iter != NULL) {
        struct ResolvQuery *next = iter->next;
        if (iter->client_free_cb != NULL)
            iter->client_free_cb(iter->client_cb_data);
        free(iter);
        iter = next;
    }
}

static void
resolver_child_main(int sockfd, char **nameservers, char **search_domains, int default_mode) {
    child_sock = sockfd;
    child_default_resolv_mode = default_mode;

#ifdef __linux__
    (void)prctl(PR_SET_NAME, "sniproxy-resolver", 0, 0, 0);
#endif
#ifdef HAVE_SETPROCTITLE
    setproctitle("sniproxy-resolver");
#endif

#ifndef SOCK_CLOEXEC
    (void)set_cloexec(child_sock);
#endif
#ifndef SOCK_NONBLOCK
    int flags = fcntl(child_sock, F_GETFL, 0);
    if (flags >= 0)
        fcntl(child_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    child_loop = ev_loop_new(EVFLAG_AUTO);
    if (child_loop == NULL)
        child_loop = EV_DEFAULT;

    resolver_child_setup_dns(child_loop, nameservers, search_domains, default_mode);

    ev_io_init(&child_ipc_watcher, resolver_child_ipc_cb, child_sock, EV_READ);
    ev_io_start(child_loop, &child_ipc_watcher);

    ev_run(child_loop, 0);

    resolver_child_cancel_all();
    resolver_child_shutdown_dns(child_loop);

    ev_io_stop(child_loop, &child_ipc_watcher);
    close(child_sock);

    if (child_loop != NULL && child_loop != EV_DEFAULT)
        ev_loop_destroy(child_loop);

    _exit(EXIT_SUCCESS);
}

static void
resolver_child_setup_dns(struct ev_loop *loop, char **nameservers,
        char **search_domains, int default_mode) {
    struct dns_ctx *ctx = &dns_defctx;
    if (nameservers == NULL) {
        dns_init(ctx, 0);
    } else {
        dns_reset(ctx);

        for (int i = 0; nameservers[i] != NULL; i++)
            dns_add_serv(ctx, nameservers[i]);

        if (search_domains != NULL)
            for (int i = 0; search_domains[i] != NULL; i++)
                dns_add_srch(ctx, search_domains[i]);
    }

    child_default_resolv_mode = default_mode;

    child_dns_sock = dns_open(ctx);
    if (child_dns_sock < 0) {
        err("resolver child: dns_open failed: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    if (set_cloexec(child_dns_sock) < 0) {
        err("resolver child: failed to set close-on-exec on DNS socket: %s",
                strerror(errno));
        _exit(EXIT_FAILURE);
    }

    int flags = fcntl(child_dns_sock, F_GETFL, 0);
    if (flags >= 0)
        fcntl(child_dns_sock, F_SETFL, flags | O_NONBLOCK);

    ev_io_init(&child_dns_io_watcher, resolver_child_dns_sock_cb, child_dns_sock, EV_READ);
    child_dns_io_watcher.data = ctx;
    ev_io_start(loop, &child_dns_io_watcher);

    ev_timer_init(&child_dns_timeout_watcher, resolver_child_dns_timeout_cb, 0.0, 0.0);
    child_dns_timeout_watcher.data = ctx;

    dns_set_tmcbck(ctx, resolver_child_dns_timer_setup_cb, loop);

    child_dns_ctx = ctx;
}

static void
resolver_child_shutdown_dns(struct ev_loop *loop) {
    if (child_dns_sock < 0)
        return;

    ev_io_stop(loop, &child_dns_io_watcher);

    if (ev_is_active(&child_dns_timeout_watcher))
        ev_timer_stop(loop, &child_dns_timeout_watcher);

    dns_close(child_dns_ctx);
    close(child_dns_sock);
    child_dns_sock = -1;
}

static void
resolver_child_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    if (!(revents & EV_READ))
        return;

    for (;;) {
        uint8_t buffer[sizeof(struct resolver_ipc_header) + RESOLVER_IPC_MAX_PAYLOAD];
        ssize_t len = recv(w->fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;

            err("resolver child recv failed: %s", strerror(errno));
            ev_break(loop, EVBREAK_ALL);
            break;
        }

        if (len == 0) {
            ev_break(loop, EVBREAK_ALL);
            break;
        }

        if (len < (ssize_t)sizeof(struct resolver_ipc_header))
            continue;

        struct resolver_ipc_header header;
        memcpy(&header, buffer, sizeof(header));

        uint32_t type = ntohl(header.type);
        uint32_t id = ntohl(header.id);
        uint32_t payload_len = ntohl(header.payload_len);

        if (payload_len > RESOLVER_IPC_MAX_PAYLOAD)
            continue;

        if ((ssize_t)payload_len != len - (ssize_t)sizeof(header))
            continue;

        const uint8_t *payload = buffer + sizeof(header);

        switch (type) {
            case RESOLVER_CMD_QUERY:
                if (payload_len < sizeof(uint32_t))
                    break;
                {
                    uint32_t mode_net;
                    memcpy(&mode_net, payload, sizeof(uint32_t));
                    int requested_mode = (int)ntohl(mode_net);
                    size_t hostname_len = payload_len - sizeof(uint32_t);
                    resolver_child_submit_query(id, requested_mode,
                            (const char *)(payload + sizeof(uint32_t)), hostname_len);
                }
                break;
            case RESOLVER_CMD_CANCEL:
                resolver_child_cancel_query(id);
                break;
            case RESOLVER_CMD_SHUTDOWN:
                ev_break(loop, EVBREAK_ALL);
                break;
            default:
                break;
        }
    }
}

static void
resolver_child_submit_query(uint32_t id, int mode,
        const char *hostname, size_t hostname_len) {
    if (hostname_len == 0 || hostname_len > RESOLVER_MAX_HOSTNAME_LEN) {
        resolver_child_send_result(id, NULL, -1);
        return;
    }

    char *hostname_copy = malloc(hostname_len + 1);
    if (hostname_copy == NULL) {
        resolver_child_send_result(id, NULL, -1);
        return;
    }
    memcpy(hostname_copy, hostname, hostname_len);
    hostname_copy[hostname_len] = '\0';

    struct ResolverChildQuery *query = calloc(1, sizeof(*query));
    if (query == NULL) {
        free(hostname_copy);
        resolver_child_send_result(id, NULL, -1);
        return;
    }

    query->id = id;
    query->resolv_mode = mode != RESOLV_MODE_DEFAULT ?
            mode : child_default_resolv_mode;
    query->hostname = hostname_copy;
    query->responses = NULL;
    query->response_count = 0;
    query->ipv4_response_count = 0;
    query->ipv6_response_count = 0;
    query->callback_completed = 0;
    query->next = child_queries;
    child_queries = query;

    memset(query->queries, 0, sizeof(query->queries));

    if (child_dns_ctx == NULL) {
        resolver_child_remove_query(query);
        resolver_child_send_result(id, NULL, -1);
        resolver_child_free_query(query);
        return;
    }

    if (query->resolv_mode != RESOLV_MODE_IPV6_ONLY) {
        query->queries[0] = dns_submit_a4(child_dns_ctx,
                hostname_copy, 0,
                resolver_child_dns_query_v4_cb, query);
        if (query->queries[0] == NULL)
            err("resolver child: failed to submit A query: %s",
                    dns_strerror(dns_status(child_dns_ctx)));
    }

    if (query->resolv_mode != RESOLV_MODE_IPV4_ONLY) {
        query->queries[1] = dns_submit_a6(child_dns_ctx,
                hostname_copy, 0,
                resolver_child_dns_query_v6_cb, query);
        if (query->queries[1] == NULL)
            err("resolver child: failed to submit AAAA query: %s",
                    dns_strerror(dns_status(child_dns_ctx)));
    }

    if (resolver_child_all_queries_are_null(query)) {
        resolver_child_process_callback(query);
        return;
    }
}

static void
resolver_child_cancel_query(uint32_t id) {
    struct ResolverChildQuery *query = resolver_child_find_query(id);
    if (query == NULL)
        return;

    resolver_child_remove_query(query);
    resolver_child_cancel_outstanding_queries(query);
    resolver_child_free_query(query);
}

static void
resolver_child_send_result(uint32_t id, const struct Address *address, int status) {
    uint32_t addr_len = 0;

    if (status == 0) {
        if (address == NULL || !address_is_sockaddr(address))
            status = -1;
        else {
            addr_len = (uint32_t)address_sa_len(address);
            if (addr_len == 0 || addr_len > RESOLVER_MAX_ADDR_LEN)
                status = -1;
        }
    }

    uint32_t status_net = htonl((uint32_t)status);
    uint32_t addr_len_net = htonl((status == 0) ? addr_len : 0);
    size_t offset = sizeof(status_net) + sizeof(addr_len_net);

    uint8_t payload[sizeof(uint32_t) * 2 + RESOLVER_MAX_ADDR_LEN];
    memcpy(payload, &status_net, sizeof(status_net));
    memcpy(payload + sizeof(status_net), &addr_len_net, sizeof(addr_len_net));

    if (status == 0 && addr_len > 0)
        memcpy(payload + offset, address_sa(address), addr_len);

    struct resolver_ipc_header header;
    header.type = htonl(RESOLVER_CMD_RESULT);
    header.id = htonl(id);
    header.payload_len = htonl((uint32_t)(offset + (status == 0 ? addr_len : 0)));

    uint8_t buffer[sizeof(header) + sizeof(payload)];
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), payload, offset + (status == 0 ? addr_len : 0));

    if (send(child_sock, buffer, sizeof(header) + offset + (status == 0 ? addr_len : 0), 0) < 0)
        err("resolver child send failed: %s", strerror(errno));
}

static void
resolver_child_cancel_all(void) {
    struct ResolverChildQuery *query = child_queries;
    child_queries = NULL;

    while (query != NULL) {
        struct ResolverChildQuery *next = query->next;
        resolver_child_cancel_outstanding_queries(query);
        resolver_child_free_query(query);
        query = next;
    }
}

static struct ResolverChildQuery *
resolver_child_find_query(uint32_t id) {
    struct ResolverChildQuery *iter = child_queries;
    while (iter != NULL) {
        if (iter->id == id)
            return iter;
        iter = iter->next;
    }
    return NULL;
}

static void
resolver_child_remove_query(struct ResolverChildQuery *query) {
    struct ResolverChildQuery **iter = &child_queries;
    while (*iter != NULL) {
        if (*iter == query) {
            *iter = query->next;
            query->next = NULL;
            return;
        }
        iter = &(*iter)->next;
    }
}

static void
resolver_child_free_query(struct ResolverChildQuery *query) {
    if (query == NULL)
        return;

    if (query->responses != NULL) {
        for (size_t i = 0; i < query->response_count; i++)
            free(query->responses[i]);
        free(query->responses);
    }

    free(query->hostname);
    free(query);
}

static void
resolver_child_dns_sock_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct dns_ctx *ctx = (struct dns_ctx *)w->data;

    if (revents & EV_READ)
        dns_ioevent(ctx, ev_now(loop));
}

static void
resolver_child_dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct dns_ctx *ctx = (struct dns_ctx *)w->data;

    if (revents & EV_TIMER)
        dns_timeouts(ctx, 30, ev_now(loop));
}

static void
resolver_child_dns_timer_setup_cb(struct dns_ctx *ctx, int timeout, void *data) {
    struct ev_loop *loop = (struct ev_loop *)data;

    if (ev_is_active(&child_dns_timeout_watcher))
        ev_timer_stop(loop, &child_dns_timeout_watcher);

    if (ctx != NULL && timeout >= 0) {
        ev_timer_set(&child_dns_timeout_watcher, timeout, 0.0);
        ev_timer_start(loop, &child_dns_timeout_watcher);
    }
}

static void
resolver_child_process_callback(struct ResolverChildQuery *query) {
    if (query->callback_completed)
        return;

    query->callback_completed = 1;

    resolver_child_cancel_outstanding_queries(query);

    struct Address *best_address = NULL;

    if (query->resolv_mode == RESOLV_MODE_IPV4_FIRST)
        best_address = resolver_child_choose_ipv4_first(query);
    else if (query->resolv_mode == RESOLV_MODE_IPV6_FIRST)
        best_address = resolver_child_choose_ipv6_first(query);
    else
        best_address = resolver_child_choose_any(query);

    resolver_child_remove_query(query);
    resolver_child_send_result(query->id, best_address, best_address == NULL ? -1 : 0);

    resolver_child_free_query(query);
}

static inline int
resolver_child_all_queries_are_null(struct ResolverChildQuery *query) {
    int result = 1;

    for (size_t i = 0; i < sizeof(query->queries) / sizeof(query->queries[0]); i++)
        result = result && query->queries[i] == NULL;

    return result;
}

static inline void
resolver_child_cancel_outstanding_queries(struct ResolverChildQuery *query) {
    for (size_t i = 0; i < sizeof(query->queries) / sizeof(query->queries[0]); i++) {
        if (query->queries[i] != NULL) {
            dns_cancel(child_dns_ctx, query->queries[i]);
            free(query->queries[i]);
            query->queries[i] = NULL;
        }
    }
}

static void
resolver_child_maybe_process_callback(struct ResolverChildQuery *query) {
    if (query->callback_completed)
        return;

    switch (query->resolv_mode) {
        case RESOLV_MODE_IPV4_ONLY:
            if (query->queries[0] == NULL)
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV6_ONLY:
            if (query->queries[1] == NULL)
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV4_FIRST:
            if (query->ipv4_response_count > 0)
                resolver_child_process_callback(query);
            else if (resolver_child_all_queries_are_null(query))
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV6_FIRST:
            if (query->ipv6_response_count > 0)
                resolver_child_process_callback(query);
            else if (resolver_child_all_queries_are_null(query))
                resolver_child_process_callback(query);
            break;
        default:
            if (query->response_count > 0)
                resolver_child_process_callback(query);
            else if (resolver_child_all_queries_are_null(query))
                resolver_child_process_callback(query);
            break;
    }
}

static struct Address *
resolver_child_choose_ipv4_first(struct ResolverChildQuery *query) {
    for (size_t i = 0; i < query->response_count; i++)
        if (address_is_sockaddr(query->responses[i]) &&
                address_sa(query->responses[i])->sa_family == AF_INET)
            return query->responses[i];

    return resolver_child_choose_any(query);
}

static struct Address *
resolver_child_choose_ipv6_first(struct ResolverChildQuery *query) {
    for (size_t i = 0; i < query->response_count; i++)
        if (address_is_sockaddr(query->responses[i]) &&
                address_sa(query->responses[i])->sa_family == AF_INET6)
            return query->responses[i];

    return resolver_child_choose_any(query);
}

static struct Address *
resolver_child_choose_any(struct ResolverChildQuery *query) {
    if (query->response_count >= 1)
        return query->responses[0];

    return NULL;
}

static void
resolver_child_dns_query_v4_cb(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
    struct ResolverChildQuery *query = (struct ResolverChildQuery *)data;

    size_t responses_added = 0;

    if (result == NULL) {
        info("resolver child: %s", dns_strerror(dns_status(ctx)));
    } else if (result->dnsa4_nrr > 0) {
        struct Address **new_responses = realloc(query->responses,
                (query->response_count + (size_t)result->dnsa4_nrr) *
                    sizeof(struct Address *));
        if (new_responses == NULL) {
            err("resolver child: failed to allocate memory for DNS responses");
        } else {
            query->responses = new_responses;

            for (int i = 0; i < result->dnsa4_nrr; i++) {
                struct sockaddr_in sa = {
                    .sin_family = AF_INET,
                    .sin_port = 0,
                    .sin_addr = result->dnsa4_addr[i],
                };

                query->responses[query->response_count] =
                        new_address_sa((struct sockaddr *)&sa, sizeof(sa));
                if (query->responses[query->response_count] == NULL)
                    err("resolver child: failed to allocate memory for DNS query result address");
                else {
                    query->response_count++;
                    responses_added++;
                }
            }
        }
    }

    query->ipv4_response_count += responses_added;

    free(result);
    query->queries[0] = NULL;

    resolver_child_maybe_process_callback(query);
}

static void
resolver_child_dns_query_v6_cb(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data) {
    struct ResolverChildQuery *query = (struct ResolverChildQuery *)data;

    size_t responses_added = 0;

    if (result == NULL) {
        info("resolver child: %s", dns_strerror(dns_status(ctx)));
    } else if (result->dnsa6_nrr > 0) {
        struct Address **new_responses = realloc(query->responses,
                (query->response_count + (size_t)result->dnsa6_nrr) *
                    sizeof(struct Address *));
        if (new_responses == NULL) {
            err("resolver child: failed to allocate memory for DNS responses");
        } else {
            query->responses = new_responses;

            for (int i = 0; i < result->dnsa6_nrr; i++) {
                struct sockaddr_in6 sa = {
                    .sin6_family = AF_INET6,
                    .sin6_port = 0,
                    .sin6_addr = result->dnsa6_addr[i],
                };

                query->responses[query->response_count] =
                        new_address_sa((struct sockaddr *)&sa, sizeof(sa));
                if (query->responses[query->response_count] == NULL)
                    err("resolver child: failed to allocate memory for DNS query result address");
                else {
                    query->response_count++;
                    responses_added++;
                }
            }
        }
    }

    query->ipv6_response_count += responses_added;

    free(result);
    query->queries[1] = NULL;

    resolver_child_maybe_process_callback(query);
}
#endif
