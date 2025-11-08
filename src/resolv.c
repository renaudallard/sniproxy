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
#include <netdb.h>
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
#include <signal.h>
#include <ares.h>
#include <ares_dns.h>
#ifndef ARES_GETSOCK_MAXNUM
#define ARES_GETSOCK_MAXNUM 16
#endif

#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "resolv.h"
#include "address.h"
#include "logger.h"
#include "fd_util.h"

/*
 * Implement DNS resolution interface using a dedicated resolver child process
 */

/* Helper macro for debug logging - only logs if resolver debug is enabled */
#define debug_log(...) do { if (get_resolver_debug()) notice(__VA_ARGS__); } while (0)

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
static struct ev_loop *resolver_loop_ref = NULL;
static char **resolver_saved_nameservers = NULL;
static char **resolver_saved_search = NULL;
static int resolver_saved_dnssec_mode = DNSSEC_VALIDATION_OFF;
static int resolver_saved_mode = RESOLV_MODE_IPV4_ONLY;

static int resolver_restart_in_progress = 0;
static pthread_mutex_t resolver_restart_lock = PTHREAD_MUTEX_INITIALIZER;


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
static int resolver_restart(void);

/* Child-side declarations */
struct ResolverChildQuery;

static void resolver_child_main(int sockfd, char **nameservers,
        char **search_domains, int default_mode, int dnssec_mode) __attribute__((noreturn));
static void resolver_child_setup_dns(struct ev_loop *loop, char **nameservers,
        char **search_domains, int default_mode, int dnssec_mode);
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
static void resolver_child_dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
static void resolver_child_deferred_free_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
static void resolver_child_schedule_timeout(struct ev_loop *loop);
static void resolver_child_cares_io_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void resolver_child_sock_state_cb(void *data, ares_socket_t socket_fd, int readable, int writable);
static void resolver_child_watch_fd(struct ev_loop *loop, ares_socket_t fd, int events);
static void resolver_child_process_callback(struct ResolverChildQuery *query);
static void resolver_child_maybe_process_callback(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_ipv4_first(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_ipv6_first(struct ResolverChildQuery *query);
static struct Address *resolver_child_choose_any(struct ResolverChildQuery *query);
static void resolver_child_dns_query_v4_cb(void *arg, int status, int timeouts, struct ares_addrinfo *result);
static void resolver_child_dns_query_v6_cb(void *arg, int status, int timeouts, struct ares_addrinfo *result);
static void resolver_child_handle_addrinfo(struct ResolverChildQuery *query, int status, struct ares_addrinfo *result, int family);
static void resolver_child_maybe_free_query(struct ResolverChildQuery *query);
static char *resolver_child_nameservers_csv(char **nameservers);

static int child_default_resolv_mode = RESOLV_MODE_IPV4_ONLY;
static int child_sock = -1;
static struct ev_loop *child_loop = NULL;
static struct ResolverChildQuery *child_queries = NULL;
static ares_channel_t *child_channel = NULL;
static int child_shutting_down = 0;
static struct ev_io child_ipc_watcher;
static struct ev_timer child_dns_timeout_watcher;
static struct ev_timer child_deferred_free_timer;
static struct ResolverChildQuery *child_queries_to_free = NULL;
struct resolver_child_cares_io {
    struct ev_io watcher;
    ares_socket_t fd;
    int events;
    int active;
};
static struct resolver_child_cares_io child_dns_watchers[ARES_GETSOCK_MAXNUM];

struct ResolverChildQuery {
    uint32_t id;
    int resolv_mode;
    size_t response_count;
    struct Address **responses;
    size_t ipv4_response_count;
    size_t ipv6_response_count;
    int callback_completed;
    int cancelled;
    int pending_v4;
    int pending_v6;
    int marked_for_free;  /* Prevents duplicate marking for deferred free */
    char *hostname;
    struct Address *best_address;
    struct ResolverChildQuery *next;
};

int
resolv_init(struct ev_loop *loop, char **nameservers, char **search, int mode, int dnssec_mode) {
    int sockets[2];
    /* Use SOCK_SEQPACKET for message boundaries with reliable delivery.
     * Falls back to SOCK_DGRAM if SEQPACKET is not available. */
#ifdef SOCK_SEQPACKET
    int socket_type = SOCK_SEQPACKET;
#else
    int socket_type = SOCK_DGRAM;
    notice("SOCK_SEQPACKET not available, using SOCK_DGRAM for resolver IPC");
#endif

    resolver_loop_ref = loop;
    resolver_saved_nameservers = nameservers;
    resolver_saved_search = search;
    resolver_saved_mode = mode;

#if !defined(ARES_FLAG_TRUSTAD)
    if (dnssec_mode == DNSSEC_VALIDATION_STRICT) {
        notice("DNSSEC strict mode requested but this c-ares build lacks Trust AD support; falling back to relaxed mode");
        dnssec_mode = DNSSEC_VALIDATION_RELAXED;
    }
#endif

    resolver_saved_dnssec_mode = dnssec_mode;

#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    socket_type |= SOCK_NONBLOCK;
#endif

    if (socketpair(AF_UNIX, socket_type, 0, sockets) < 0) {
#ifdef SOCK_SEQPACKET
        /* SEQPACKET might not be supported, try DGRAM as fallback */
        if (errno == EPROTONOSUPPORT || errno == EPROTOTYPE) {
            notice("SOCK_SEQPACKET not supported, falling back to SOCK_DGRAM for resolver IPC");
            socket_type = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
            socket_type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
            socket_type |= SOCK_NONBLOCK;
#endif
            if (socketpair(AF_UNIX, socket_type, 0, sockets) < 0)
                fatal("resolver socketpair failed: %s", strerror(errno));
        } else
#endif
            fatal("resolver socketpair failed: %s", strerror(errno));
    }

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
        resolver_child_main(sockets[1], nameservers, search, mode,
                dnssec_mode);
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
        /* Only send SHUTDOWN if not restarting (socket may be dead during restart) */
        pthread_mutex_lock(&resolver_restart_lock);
        int restarting = resolver_restart_in_progress;
        pthread_mutex_unlock(&resolver_restart_lock);
        if (!restarting) {
            resolver_send_message(RESOLVER_CMD_SHUTDOWN, 0, NULL, 0);
        }
        close(resolver_sock);
        resolver_sock = -1;
    }

    if (resolver_pid > 0) {
        int status;
        pid_t result = waitpid(resolver_pid, &status, WNOHANG);
        if (result < 0) {
            /* ECHILD means child was already reaped, not an error */
            if (errno != ECHILD)
                err("waitpid on resolver failed: %s", strerror(errno));
        } else if (result == 0) {
            /* Child still running, wait for it */
            if (waitpid(resolver_pid, &status, 0) < 0 && errno != ECHILD)
                err("waitpid on resolver failed: %s", strerror(errno));
        }
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
        pthread_mutex_lock(&resolver_restart_lock);
        int restarting = resolver_restart_in_progress;
        pthread_mutex_unlock(&resolver_restart_lock);
        if (!restarting &&
                (errno == EDESTADDRREQ || errno == ENOTCONN || errno == ECONNRESET || errno == EPIPE)) {
            if (resolver_restart() < 0)
                err("resolver restart failed");
        }
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
            /* Trigger restart on recv failures indicating dead child */
            pthread_mutex_lock(&resolver_restart_lock);
            int restarting = resolver_restart_in_progress;
            pthread_mutex_unlock(&resolver_restart_lock);
            if (!restarting &&
                    (errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE)) {
                if (resolver_restart() < 0)
                    err("resolver restart failed");
            }
            break;
        }

        if (len == 0) {
            warn("resolver socket closed by child");
            ev_io_stop(loop, w);
            if (resolver_sock >= 0) {
                close(resolver_sock);
                resolver_sock = -1;
            }
            /* Child exited unexpectedly, restart if not shutting down */
            pthread_mutex_lock(&resolver_restart_lock);
            int restarting = resolver_restart_in_progress;
            pthread_mutex_unlock(&resolver_restart_lock);
            if (!restarting) {
                if (resolver_restart() < 0)
                    err("resolver restart failed");
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

static int
resolver_restart(void) {
    if (resolver_loop_ref == NULL)
        return -1;

    /* Prevent concurrent restart attempts */
    pthread_mutex_lock(&resolver_restart_lock);
    if (resolver_restart_in_progress) {
        pthread_mutex_unlock(&resolver_restart_lock);
        return -1;
    }
    resolver_restart_in_progress = 1;
    pthread_mutex_unlock(&resolver_restart_lock);

    notice("resolver child restarting after IPC failure");
    resolv_shutdown(resolver_loop_ref);
    int rc = resolv_init(resolver_loop_ref, resolver_saved_nameservers,
            resolver_saved_search, resolver_saved_mode,
            resolver_saved_dnssec_mode);

    pthread_mutex_lock(&resolver_restart_lock);
    resolver_restart_in_progress = 0;
    pthread_mutex_unlock(&resolver_restart_lock);

    return rc;
}

static void
resolver_child_crash_handler(int signum) {
    /* Use only async-signal-safe functions (write is safe, err/printf/strlen are not) */
    const char msg_prefix[] = "resolver child crashed with signal ";
    const char *signame = NULL;
    size_t signame_len = 0;

    switch (signum) {
        case SIGSEGV:
            signame = "SIGSEGV (segmentation fault)\n";
            signame_len = 30;
            break;
        case SIGBUS:
            signame = "SIGBUS (bus error)\n";
            signame_len = 19;
            break;
        case SIGABRT:
            signame = "SIGABRT (abort)\n";
            signame_len = 16;
            break;
        case SIGILL:
            signame = "SIGILL (illegal instruction)\n";
            signame_len = 30;
            break;
        case SIGFPE:
            signame = "SIGFPE (floating point exception)\n";
            signame_len = 35;
            break;
        default:
            signame = "UNKNOWN\n";
            signame_len = 8;
            break;
    }

    /* write() is async-signal-safe */
    (void)write(STDERR_FILENO, msg_prefix, sizeof(msg_prefix) - 1);
    if (signame != NULL)
        (void)write(STDERR_FILENO, signame, signame_len);

    /* Signal handler will be reset by SA_RESETHAND, so signal will terminate process */
}

static void
resolver_child_main(int sockfd, char **nameservers, char **search_domains, int default_mode, int dnssec_mode) {
    child_sock = sockfd;
    child_default_resolv_mode = default_mode;

    notice("resolver child starting (pid=%d)", getpid());
    debug_log("resolver child: debug logging ENABLED");

    /* Install crash handlers to log what went wrong */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = resolver_child_crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND; /* Reset to default after first signal */
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);

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

    int ares_status = ares_library_init(ARES_LIB_INIT_ALL);
    if (ares_status != ARES_SUCCESS) {
        err("resolver child: ares_library_init failed: %s", ares_strerror(ares_status));
        _exit(EXIT_FAILURE);
    }

    resolver_child_setup_dns(child_loop, nameservers, search_domains,
            default_mode, dnssec_mode);

    ev_io_init(&child_ipc_watcher, resolver_child_ipc_cb, child_sock, EV_READ);
    ev_io_start(child_loop, &child_ipc_watcher);

    ev_run(child_loop, 0);

    resolver_child_cancel_all();
    resolver_child_shutdown_dns(child_loop);
    ares_library_cleanup();

    ev_io_stop(child_loop, &child_ipc_watcher);
    close(child_sock);

    if (child_loop != NULL && child_loop != EV_DEFAULT)
        ev_loop_destroy(child_loop);

    _exit(EXIT_SUCCESS);
}

static void
resolver_child_setup_dns(struct ev_loop *loop, char **nameservers,
        char **search_domains, int default_mode, int dnssec_mode) {
    struct ares_options options;
    for (size_t i = 0; i < sizeof(child_dns_watchers) / sizeof(child_dns_watchers[0]); i++) {
        child_dns_watchers[i].active = 0;
        child_dns_watchers[i].events = 0;
        child_dns_watchers[i].fd = ARES_SOCKET_BAD;
    }

    struct ares_options *options_ptr = NULL;
    int optmask = 0;
    memset(&options, 0, sizeof(options));

    options.sock_state_cb = resolver_child_sock_state_cb;
    options.sock_state_cb_data = loop;
    optmask |= ARES_OPT_SOCK_STATE_CB;
    options_ptr = &options;

    if (dnssec_mode != DNSSEC_VALIDATION_OFF) {
#ifdef ARES_FLAG_EDNS
        options.flags |= ARES_FLAG_EDNS;
#endif
#ifdef ARES_FLAG_DNSSECOK
        options.flags |= ARES_FLAG_DNSSECOK;
#endif
    }

#if defined(ARES_FLAG_TRUSTAD)
    if (dnssec_mode == DNSSEC_VALIDATION_STRICT) {
        options.flags |= ARES_FLAG_TRUSTAD;
    }
#else
    if (dnssec_mode == DNSSEC_VALIDATION_STRICT) {
        err("resolver child: DNSSEC strict mode requested but not supported by this c-ares build; falling back to relaxed mode");
        dnssec_mode = DNSSEC_VALIDATION_RELAXED;
    }
#endif

    if (options.flags != 0)
        optmask |= ARES_OPT_FLAGS;

    if (search_domains != NULL && search_domains[0] != NULL) {
        int ndomains = 0;
        while (search_domains[ndomains] != NULL)
            ndomains++;
        options.domains = search_domains;
        options.ndomains = ndomains;
        optmask |= ARES_OPT_DOMAINS;
    }

    int status = ares_init_options(&child_channel, options_ptr, optmask);
    if (status != ARES_SUCCESS) {
        err("resolver child: ares_init failed: %s", ares_strerror(status));
        _exit(EXIT_FAILURE);
    }

    if (nameservers != NULL && nameservers[0] != NULL) {
        char *csv = resolver_child_nameservers_csv(nameservers);
        if (csv == NULL) {
            err("resolver child: failed to allocate nameserver list");
            _exit(EXIT_FAILURE);
        }
        status = ares_set_servers_csv(child_channel, csv);
        free(csv);
        if (status != ARES_SUCCESS) {
            err("resolver child: ares_set_servers_csv failed: %s", ares_strerror(status));
            _exit(EXIT_FAILURE);
        }
    }

    child_default_resolv_mode = default_mode;

    ev_timer_init(&child_dns_timeout_watcher, resolver_child_dns_timeout_cb, 0.0, 0.0);
    ev_timer_init(&child_deferred_free_timer, resolver_child_deferred_free_cb, 0.0, 0.0);

    resolver_child_schedule_timeout(loop);
}

static void
resolver_child_shutdown_dns(struct ev_loop *loop) {
    for (size_t i = 0; i < sizeof(child_dns_watchers) / sizeof(child_dns_watchers[0]); i++) {
        if (child_dns_watchers[i].active) {
            ev_io_stop(loop, &child_dns_watchers[i].watcher);
            child_dns_watchers[i].active = 0;
        }
        child_dns_watchers[i].events = 0;
        child_dns_watchers[i].fd = ARES_SOCKET_BAD;
    }

    if (ev_is_active(&child_dns_timeout_watcher))
        ev_timer_stop(loop, &child_dns_timeout_watcher);

    if (ev_is_active(&child_deferred_free_timer))
        ev_timer_stop(loop, &child_deferred_free_timer);

    if (child_channel != NULL) {
        /* ares_destroy will invoke callbacks for all pending queries.
         * After it returns, c-ares no longer holds any query pointers. */
        ares_destroy(child_channel);
        child_channel = NULL;
    }

    /* Free any remaining queries that weren't freed by callbacks.
     * This can happen if callbacks failed to allocate memory or
     * if there were internal c-ares issues. */
    struct ResolverChildQuery *query = child_queries;
    child_queries = NULL;
    while (query != NULL) {
        struct ResolverChildQuery *next = query->next;
        resolver_child_free_query(query);
        query = next;
    }

    /* Free any queries pending deferred free */
    query = child_queries_to_free;
    child_queries_to_free = NULL;
    while (query != NULL) {
        struct ResolverChildQuery *next = query->next;
        resolver_child_free_query(query);
        query = next;
    }
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

            err("resolver child recv failed: %s (errno=%d), exiting", strerror(errno), errno);
            ev_break(loop, EVBREAK_ALL);
            break;
        }

        if (len == 0) {
            notice("resolver child: parent closed socket, exiting");
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
    query->cancelled = 0;
    query->pending_v4 = 0;
    query->pending_v6 = 0;
    query->marked_for_free = 0;
    query->next = child_queries;
    child_queries = query;

    if (child_channel == NULL) {
        resolver_child_remove_query(query);
        resolver_child_send_result(id, NULL, -1);
        resolver_child_free_query(query);
        return;
    }

    if (query->resolv_mode != RESOLV_MODE_IPV6_ONLY) {
        struct ares_addrinfo_hints hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
        };
        query->pending_v4 = 1;
        ares_getaddrinfo(child_channel, hostname_copy, NULL, &hints,
                resolver_child_dns_query_v4_cb, query);
    }

    if (query->resolv_mode != RESOLV_MODE_IPV4_ONLY) {
        struct ares_addrinfo_hints hints = {
            .ai_family = AF_INET6,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
        };
        query->pending_v6 = 1;
        ares_getaddrinfo(child_channel, hostname_copy, NULL, &hints,
                resolver_child_dns_query_v6_cb, query);
    }

    if (query->pending_v4 == 0 && query->pending_v6 == 0) {
        resolver_child_process_callback(query);
        resolver_child_maybe_free_query(query);
        return;
    }

    resolver_child_schedule_timeout(child_loop);
}

static void
resolver_child_cancel_query(uint32_t id) {
    struct ResolverChildQuery *query = resolver_child_find_query(id);
    if (query == NULL)
        return;

    resolver_child_remove_query(query);
    query->cancelled = 1;

    resolver_child_maybe_free_query(query);
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

    if (send(child_sock, buffer, sizeof(header) + offset + (status == 0 ? addr_len : 0), 0) < 0) {
        err("resolver child send failed: %s (errno=%d)", strerror(errno), errno);
        /* If parent socket is dead, child should exit gracefully */
        if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN) {
            notice("resolver child: parent socket dead, exiting");
            if (child_loop != NULL)
                ev_break(child_loop, EVBREAK_ALL);
        }
    }
}

static void
resolver_child_cancel_all(void) {
    /* Set shutdown flag to prevent callbacks from freeing queries.
     * Mark all queries as cancelled but don't free them yet.
     * The cleanup will happen in shutdown_dns after ares_destroy(). */
    child_shutting_down = 1;

    struct ResolverChildQuery *query = child_queries;
    while (query != NULL) {
        query->cancelled = 1;
        query = query->next;
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
resolver_child_deferred_free_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    (void)loop;
    (void)revents;
    (void)w;

    debug_log("resolver child: deferred_free_cb processing free list");

    struct ResolverChildQuery *query = child_queries_to_free;
    child_queries_to_free = NULL;

    while (query != NULL) {
        struct ResolverChildQuery *next = query->next;
        query->next = NULL;

        uint32_t query_id = query->id;
        debug_log("resolver child: deferred free_query START query_id=%u response_count=%zu",
                  query_id, query->response_count);

        if (query->responses != NULL) {
            for (size_t i = 0; i < query->response_count; i++) {
                if (query->responses[i] != NULL)
                    free(query->responses[i]);
            }
            free(query->responses);
        }

        free(query->hostname);
        free(query);

        debug_log("resolver child: deferred free_query END query_id=%u", query_id);

        query = next;
    }

    debug_log("resolver child: deferred_free_cb complete");
}

static void
resolver_child_free_query(struct ResolverChildQuery *query) {
    if (query == NULL)
        return;

    uint32_t query_id = query->id;
    debug_log("resolver child: free_query START query_id=%u response_count=%zu",
              query_id, query->response_count);

    if (query->responses != NULL) {
        for (size_t i = 0; i < query->response_count; i++) {
            if (query->responses[i] != NULL)
                free(query->responses[i]);
        }
        free(query->responses);
    }

    free(query->hostname);
    free(query);

    debug_log("resolver child: free_query END query_id=%u", query_id);
}

static struct resolver_child_cares_io *
resolver_child_find_watch_slot(ares_socket_t fd) {
    for (size_t i = 0; i < sizeof(child_dns_watchers) / sizeof(child_dns_watchers[0]); i++) {
        if (child_dns_watchers[i].active && child_dns_watchers[i].fd == fd)
            return &child_dns_watchers[i];
    }

    return NULL;
}

static struct resolver_child_cares_io *
resolver_child_get_free_watch_slot(void) {
    for (size_t i = 0; i < sizeof(child_dns_watchers) / sizeof(child_dns_watchers[0]); i++)
        if (!child_dns_watchers[i].active)
            return &child_dns_watchers[i];

    return NULL;
}

static void
resolver_child_watch_fd(struct ev_loop *loop, ares_socket_t fd, int events) {
    struct resolver_child_cares_io *slot = resolver_child_find_watch_slot(fd);

    if (events == 0) {
        if (slot != NULL && slot->active) {
            ev_io_stop(loop, &slot->watcher);
            slot->active = 0;
            slot->events = 0;
            slot->fd = ARES_SOCKET_BAD;
        }
        return;
    }

    if (slot == NULL) {
        slot = resolver_child_get_free_watch_slot();
        if (slot == NULL) {
            err("resolver child: no free watcher slots for DNS sockets");
            return;
        }
        slot->fd = fd;
        slot->events = events;
        ev_io_init(&slot->watcher, resolver_child_cares_io_cb, fd, events);
        slot->active = 1;
        ev_io_start(loop, &slot->watcher);
        return;
    }

    if (!slot->active) {
        ev_io_init(&slot->watcher, resolver_child_cares_io_cb, fd, events);
        slot->events = events;
        slot->active = 1;
        ev_io_start(loop, &slot->watcher);
        return;
    }

    if (slot->events != events) {
        ev_io_stop(loop, &slot->watcher);
        ev_io_set(&slot->watcher, fd, events);
        slot->events = events;
        ev_io_start(loop, &slot->watcher);
    }
}

static void
resolver_child_sock_state_cb(void *data, ares_socket_t socket_fd, int readable, int writable) {
    struct ev_loop *loop = (struct ev_loop *)data;
    int events = 0;

    if (readable)
        events |= EV_READ;
    if (writable)
        events |= EV_WRITE;

    resolver_child_watch_fd(loop, socket_fd, events);
    resolver_child_schedule_timeout(loop);
}

static void
resolver_child_cares_io_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    if (child_channel == NULL)
        return;

    ares_socket_t read_fd = (revents & EV_READ) ? w->fd : ARES_SOCKET_BAD;
    ares_socket_t write_fd = (revents & EV_WRITE) ? w->fd : ARES_SOCKET_BAD;

    ares_process_fd(child_channel, read_fd, write_fd);

    resolver_child_schedule_timeout(loop);
}

static void
resolver_child_dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w __attribute__((unused)), int revents) {
    if (!(revents & EV_TIMER) || child_channel == NULL)
        return;

    ares_process_fd(child_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    resolver_child_schedule_timeout(loop);
}

static void
resolver_child_schedule_timeout(struct ev_loop *loop) {
    if (child_channel == NULL)
        return;

    struct timeval tv = { 0, 0 };
    struct timeval *next_timeout = ares_timeout(child_channel, NULL, &tv);

    if (next_timeout == NULL) {
        if (ev_is_active(&child_dns_timeout_watcher))
            ev_timer_stop(loop, &child_dns_timeout_watcher);
        return;
    }

    ev_tstamp after = next_timeout->tv_sec + next_timeout->tv_usec / 1000000.0;
    if (after < 0.0)
        after = 0.0;

    ev_timer_set(&child_dns_timeout_watcher, after, 0.0);
    if (!ev_is_active(&child_dns_timeout_watcher))
        ev_timer_start(loop, &child_dns_timeout_watcher);
}


static void
resolver_child_process_callback(struct ResolverChildQuery *query) {
    if (query == NULL) {
        err("resolver child: process_callback called with NULL query");
        return;
    }

    if (query->callback_completed || query->cancelled) {
        debug_log("resolver child: process_callback SKIP query_id=%u (callback_completed=%d cancelled=%d)",
                  query->id, query->callback_completed, query->cancelled);
        return;
    }

    debug_log("resolver child: process_callback PROCESSING query_id=%u responses=%zu",
              query->id, query->response_count);

    query->callback_completed = 1;

    struct Address *best_address = NULL;

    if (query->resolv_mode == RESOLV_MODE_IPV4_FIRST)
        best_address = resolver_child_choose_ipv4_first(query);
    else if (query->resolv_mode == RESOLV_MODE_IPV6_FIRST)
        best_address = resolver_child_choose_ipv6_first(query);
    else
        best_address = resolver_child_choose_any(query);

    /* During shutdown, keep queries in the list so cleanup can free them all.
     * During normal operation, remove from list so it can be freed when ready. */
    if (!child_shutting_down) {
        debug_log("resolver child: removing query_id=%u from list", query->id);
        resolver_child_remove_query(query);
    }

    if (!query->cancelled) {
        debug_log("resolver child: sending result for query_id=%u", query->id);
        resolver_child_send_result(query->id, best_address, best_address == NULL ? -1 : 0);
    }

    /* Query lifetime is managed by the caller once pending lookups finish. */
}

static char *
resolver_child_nameservers_csv(char **nameservers) {
    size_t total_len = 0;
    size_t count = 0;

    for (size_t i = 0; nameservers[i] != NULL; i++) {
        total_len += strlen(nameservers[i]) + 1;
        count++;
    }

    if (count == 0)
        return NULL;

    char *csv = malloc(total_len);
    if (csv == NULL)
        return NULL;

    char *ptr = csv;
    for (size_t i = 0; nameservers[i] != NULL; i++) {
        size_t len = strlen(nameservers[i]);
        memcpy(ptr, nameservers[i], len);
        ptr += len;
        if (nameservers[i + 1] != NULL)
            *ptr++ = ',';
    }
    *ptr = '\0';

    return csv;
}

static void
resolver_child_maybe_free_query(struct ResolverChildQuery *query) {
    if (query == NULL) {
        err("resolver child: maybe_free_query called with NULL query");
        return;
    }

    /* During shutdown, don't free queries here. Let shutdown_dns handle it
     * after ares_destroy() completes to avoid use-after-free. */
    if (child_shutting_down)
        return;

    if (query->pending_v4 == 0 && query->pending_v6 == 0 &&
            (query->callback_completed || query->cancelled)) {

        /* Check if already marked to prevent duplicate free */
        if (query->marked_for_free) {
            debug_log("resolver child: query_id=%u already marked for free, skipping", query->id);
            return;
        }

        debug_log("resolver child: MARKING query_id=%u for deferred free (callback_completed=%d cancelled=%d)",
                  query->id, query->callback_completed, query->cancelled);

        query->marked_for_free = 1;

        /* Add to deferred free list instead of freeing immediately.
         * This prevents use-after-free if c-ares calls another callback
         * with the same pointer after we return from this callback. */
        query->next = child_queries_to_free;
        child_queries_to_free = query;

        /* Schedule immediate timer to free queries outside of c-ares callbacks */
        if (!ev_is_active(&child_deferred_free_timer)) {
            ev_timer_set(&child_deferred_free_timer, 0.0, 0.0);
            ev_timer_start(child_loop, &child_deferred_free_timer);
        }
    }
}

static void
resolver_child_maybe_process_callback(struct ResolverChildQuery *query) {
    if (query == NULL)
        return;

    if (query->callback_completed || query->cancelled)
        return;

    switch (query->resolv_mode) {
        case RESOLV_MODE_IPV4_ONLY:
            if (query->pending_v4 == 0)
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV6_ONLY:
            if (query->pending_v6 == 0)
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV4_FIRST:
            if (query->ipv4_response_count > 0)
                resolver_child_process_callback(query);
            else if (query->pending_v4 == 0 && query->pending_v6 == 0)
                resolver_child_process_callback(query);
            break;
        case RESOLV_MODE_IPV6_FIRST:
            if (query->ipv6_response_count > 0)
                resolver_child_process_callback(query);
            else if (query->pending_v4 == 0 && query->pending_v6 == 0)
                resolver_child_process_callback(query);
            break;
        default:
            if (query->response_count > 0)
                resolver_child_process_callback(query);
            else if (query->pending_v4 == 0 && query->pending_v6 == 0)
                resolver_child_process_callback(query);
            break;
    }
}

static struct Address *
resolver_child_choose_ipv4_first(struct ResolverChildQuery *query) {
    if (query == NULL || query->responses == NULL)
        return NULL;

    for (size_t i = 0; i < query->response_count; i++) {
        if (query->responses[i] == NULL)
            continue;
        if (!address_is_sockaddr(query->responses[i]))
            continue;
        const struct sockaddr *sa = address_sa(query->responses[i]);
        if (sa == NULL)
            continue;
        if (sa->sa_family == AF_INET)
            return query->responses[i];
    }

    return resolver_child_choose_any(query);
}

static struct Address *
resolver_child_choose_ipv6_first(struct ResolverChildQuery *query) {
    if (query == NULL || query->responses == NULL)
        return NULL;

    for (size_t i = 0; i < query->response_count; i++) {
        if (query->responses[i] == NULL)
            continue;
        if (!address_is_sockaddr(query->responses[i]))
            continue;
        const struct sockaddr *sa = address_sa(query->responses[i]);
        if (sa == NULL)
            continue;
        if (sa->sa_family == AF_INET6)
            return query->responses[i];
    }

    return resolver_child_choose_any(query);
}

static struct Address *
resolver_child_choose_any(struct ResolverChildQuery *query) {
    if (query == NULL || query->responses == NULL)
        return NULL;

    if (query->response_count >= 1 && query->responses[0] != NULL)
        return query->responses[0];

    return NULL;
}

static void
resolver_child_dns_query_v4_cb(void *arg, int status, int timeouts __attribute__((unused)), struct ares_addrinfo *result) {
    struct ResolverChildQuery *query = (struct ResolverChildQuery *)arg;

    if (query == NULL) {
        err("resolver child: v4 callback received NULL query pointer");
        if (result != NULL)
            ares_freeaddrinfo(result);
        return;
    }

    resolver_child_handle_addrinfo(query, status, result, AF_INET);
}

static void
resolver_child_dns_query_v6_cb(void *arg, int status, int timeouts __attribute__((unused)), struct ares_addrinfo *result) {
    struct ResolverChildQuery *query = (struct ResolverChildQuery *)arg;

    if (query == NULL) {
        err("resolver child: v6 callback received NULL query pointer");
        if (result != NULL)
            ares_freeaddrinfo(result);
        return;
    }

    resolver_child_handle_addrinfo(query, status, result, AF_INET6);
}

static void
resolver_child_handle_addrinfo(struct ResolverChildQuery *query, int status, struct ares_addrinfo *result, int family) {
    size_t responses_added = 0;

    if (query == NULL) {
        err("resolver child: handle_addrinfo received NULL query, status=%d family=%d", status, family);
        if (result != NULL)
            ares_freeaddrinfo(result);
        return;
    }

    debug_log("resolver child: handle_addrinfo START query_id=%u family=%d status=%d pending_v4=%d pending_v6=%d callback_completed=%d",
              query->id, family, status, query->pending_v4, query->pending_v6, query->callback_completed);

    if (status == ARES_SUCCESS && result != NULL) {
        for (struct ares_addrinfo_node *node = result->nodes; node != NULL; node = node->ai_next) {
            if (node->ai_family != family || node->ai_addr == NULL)
                continue;

            struct Address *response = new_address_sa(node->ai_addr, (socklen_t)node->ai_addrlen);
            if (response == NULL) {
                err("resolver child: failed to allocate memory for DNS query result address");
                continue;
            }

            /* Check for overflow before realloc */
            if (query->response_count >= SIZE_MAX / sizeof(struct Address *) - 1) {
                err("resolver child: too many DNS responses, cannot expand list");
                free(response);
                break;
            }

            struct Address **tmp = realloc(query->responses,
                    (query->response_count + 1) * sizeof(struct Address *));
            if (tmp == NULL) {
                err("resolver child: failed to expand DNS response list");
                free(response);
                break;
            }

            query->responses = tmp;
            query->responses[query->response_count++] = response;
            responses_added++;
        }
    } else if (status != ARES_ENOTFOUND && status != ARES_ENODATA && status != ARES_EDESTRUCTION) {
        info("resolver child: %s", ares_strerror(status));
    }

    if (result != NULL)
        ares_freeaddrinfo(result);

    if (family == AF_INET)
        query->ipv4_response_count += responses_added;
    else
        query->ipv6_response_count += responses_added;

    /* Save query ID early to avoid any use-after-free */
    uint32_t saved_query_id = query->id;

    if (family == AF_INET) {
        debug_log("resolver child: query_id=%u marking v4 complete", saved_query_id);
        query->pending_v4 = 0;
    } else {
        debug_log("resolver child: query_id=%u marking v6 complete", saved_query_id);
        query->pending_v6 = 0;
    }

    debug_log("resolver child: query_id=%u calling maybe_process_callback (pending_v4=%d pending_v6=%d)",
              saved_query_id, query->pending_v4, query->pending_v6);
    resolver_child_maybe_process_callback(query);

    debug_log("resolver child: query_id=%u calling maybe_free_query", saved_query_id);
    resolver_child_maybe_free_query(query);

    debug_log("resolver child: query_id=%u handle_addrinfo END", saved_query_id);
}
