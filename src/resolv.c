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
#include <sys/uio.h>
#include <ares.h>
#include <ares_dns.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#ifndef ARES_GETSOCK_MAXNUM
#define ARES_GETSOCK_MAXNUM 16
#endif

#if !(defined(HAVE_ARC4RANDOM) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__) || defined(__linux__))
#error "arc4random() is required (available on OpenBSD, FreeBSD, NetBSD, macOS, and modern Linux)."
#endif

#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "resolv.h"
#include "address.h"
#include "logger.h"
#include "fd_util.h"
#include "ipc_crypto.h"

/*
 * Implement DNS resolution interface using a dedicated resolver child process
 */

/* Helper macro for debug logging - only logs if resolver debug is enabled */
#define debug_log(...) do { if (get_resolver_debug()) notice(__VA_ARGS__); } while (0)

#define RESOLVER_CMD_QUERY      1u
#define RESOLVER_CMD_CANCEL     2u
#define RESOLVER_CMD_RESULT     3u
#define RESOLVER_CMD_SHUTDOWN   4u
#define RESOLVER_CMD_CRASH     5u

#define RESOLVER_MAX_HOSTNAME_LEN    1023
#define RESOLVER_IPC_MAX_PAYLOAD     4096
#define RESOLVER_IPC_MAX_FRAME        (sizeof(struct resolver_ipc_header) + \
        RESOLVER_IPC_MAX_PAYLOAD + IPC_CRYPTO_OVERHEAD)
#define RESOLVER_MAX_ADDR_LEN        ((size_t)sizeof(struct sockaddr_storage))
#define RESOLVER_MAX_DNS_RESPONSES   64

struct resolver_ipc_header {
    uint32_t type;
    uint32_t id;
    uint32_t payload_len;
};

struct ResolverPending;

struct ResolvQuery {
    struct ResolverPending *pending;
    void (*client_cb)(struct Address *, void *);
    void (*client_free_cb)(void *);
    void *client_cb_data;
    struct ResolvQuery *next_client;
};

struct ResolverPending {
    uint32_t id;
    int resolv_mode;
    char *hostname;
    size_t hostname_len;
    uint32_t host_hash;
    struct ResolvQuery *clients;
    struct ResolverPending *next_id;
    struct ResolverPending *next_host;
};

struct ResolverDotServer {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char *sni_hostname;
    int verify_certificate;
};

struct ResolverChildDotSocket {
    ares_socket_t fd;
    struct ResolverDotServer *server;
    SSL *ssl;
    int handshake_complete;
    int forcing_events;
    int base_events;
    int failed;
    struct ResolverChildDotSocket *next;
};

#define RESOLVER_IPC_CHANNEL_ID 0x52535652u

static int resolver_sock = -1;
static pid_t resolver_pid = -1;
static struct ipc_crypto_state resolver_ipc_crypto;
static uint32_t resolver_next_query_prng(void);
#define RESOLVER_QUERY_BUCKETS 1024u
#define RESOLVER_HOST_BUCKETS 2048u
static struct ResolverPending *resolver_queries[RESOLVER_QUERY_BUCKETS];
static struct ResolverPending *resolver_hosts[RESOLVER_HOST_BUCKETS];
static uint32_t resolver_bucket_salt;
static inline size_t resolver_query_bucket_index(uint32_t id) {
    uint32_t mixed = id ^ resolver_bucket_salt;
    mixed ^= mixed >> 16;
    return mixed & (RESOLVER_QUERY_BUCKETS - 1u);
}
static inline size_t resolver_host_bucket_index(uint32_t hash) {
    return hash & (RESOLVER_HOST_BUCKETS - 1u);
}

static uint32_t
resolver_hostname_hash(const char *hostname, size_t len, int mode) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)hostname[i];
        hash *= 16777619u;
    }
    hash ^= (uint32_t)mode;
    hash *= 16777619u;
    return hash ? hash : 0x9e3779b1u;
}

static struct ResolverPending *
resolver_find_pending_host(const char *hostname, size_t len, int mode, uint32_t hash) {
    size_t bucket = resolver_host_bucket_index(hash);
    struct ResolverPending *iter = resolver_hosts[bucket];
    while (iter != NULL) {
        if (iter->resolv_mode == mode && iter->host_hash == hash &&
                iter->hostname_len == len &&
                memcmp(iter->hostname, hostname, len) == 0)
            return iter;
        iter = iter->next_host;
    }
    return NULL;
}
static uint32_t
resolver_next_query_prng(void) {
    /* arc4random() delivers cryptographically secure random numbers. */
    return arc4random();
}

static pthread_mutex_t resolver_queries_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ev_io resolver_ipc_watcher;
static int default_resolv_mode = RESOLV_MODE_IPV4_ONLY;
static struct ev_loop *resolver_loop_ref = NULL;
static char **resolver_saved_nameservers = NULL;
static char **resolver_saved_search = NULL;
static int resolver_saved_dnssec_mode = DEFAULT_DNSSEC_VALIDATION_MODE;
static int resolver_saved_mode = RESOLV_MODE_IPV4_ONLY;

static int resolver_restart_in_progress = 0;
static pthread_mutex_t resolver_restart_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ResolverPending *resolver_pending_restart_list = NULL;
static struct ResolverDotServer *child_dot_servers = NULL;
static size_t child_dot_server_count = 0;
static size_t child_dot_server_capacity = 0;
static SSL_CTX *child_dot_ssl_ctx = NULL;
static struct ResolverChildDotSocket *child_dot_socket_list = NULL;

static const char *resolver_cafile_fallbacks[] = {
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
    NULL
};

static const char *resolver_cadir_fallbacks[] = {
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    NULL
};


/* Parent-side helpers */
static int resolver_send_message(uint32_t type, uint32_t id,
        const void *payload, size_t payload_len);
static void resolver_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static void resolver_process_datagram(const uint8_t *buffer, ssize_t len);
static void resolver_handle_crash_notice(const uint8_t *payload, size_t payload_len);
static void resolver_handle_result(uint32_t id, const uint8_t *payload, size_t payload_len);
static int resolver_emit_query(struct ResolverPending *pending);
static void resolver_attach_query(struct ResolverPending *pending);
static struct ResolverPending *resolver_take_query(uint32_t id);
static void resolver_remove_pending(struct ResolverPending *pending);
static struct ResolverPending *resolver_find_pending_host(const char *hostname, size_t len, int mode, uint32_t hash);
static struct ResolverPending *resolver_detach_pending_queries(void);
static void resolver_cleanup_pending_queries(void);
static void resolver_free_pending_list(struct ResolverPending *list, int notify_clients);
static uint32_t resolver_hostname_hash(const char *hostname, size_t len, int mode);
static int resolver_restart(void);
static void resolver_resubmit_pending_queries(void);
static void resolver_fail_pending_restart_list(void);

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
static int resolver_child_process_nameservers(char **nameservers, char ***processed_out);
static void resolver_child_free_processed_nameservers(char **list);
static void resolver_child_free_dot_servers(void);
static int resolver_child_handle_dot_server(const char *target, char **converted);
static struct ResolverDotServer *resolver_child_find_dot_server_sa(const struct sockaddr *addr, ares_socklen_t addrlen);
static int resolver_child_sockaddr_equal(const struct sockaddr *a, ares_socklen_t alen,
        const struct sockaddr *b, ares_socklen_t blen);
static int resolver_child_init_dot_ssl_ctx(void);
static void resolver_child_free_dot_ssl_ctx(void);
static struct ResolverChildDotSocket *resolver_child_dot_socket_get(ares_socket_t fd);
static void resolver_child_dot_socket_detach(ares_socket_t fd);
static int resolver_child_dot_socket_attach(ares_socket_t fd, struct ResolverDotServer *server);
static int resolver_child_dot_ensure_handshake(struct ResolverChildDotSocket *sock);
static ares_socket_t resolver_child_dot_asocket(int domain, int type, int protocol, void *user_data);
static int resolver_child_dot_aclose(ares_socket_t fd, void *user_data);
static int resolver_child_dot_aconnect(ares_socket_t fd, const struct sockaddr *address, ares_socklen_t addrlen, void *user_data);
static ares_ssize_t resolver_child_dot_arecvfrom(ares_socket_t fd, void *buffer, size_t len, int flags,
        struct sockaddr *addr, ares_socklen_t *addrlen, void *user_data);
static ares_ssize_t resolver_child_dot_asendv(ares_socket_t fd, const struct iovec *iov, int iovcnt, void *user_data);
static const struct ares_socket_functions resolver_child_dot_socket_functions;

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
    ipc_crypto_channel_init(&resolver_ipc_crypto, RESOLVER_IPC_CHANNEL_ID,
            IPC_CRYPTO_ROLE_PARENT);
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

    if (resolver_bucket_salt == 0) {
        resolver_bucket_salt = arc4random();
        if (resolver_bucket_salt == 0)
            resolver_bucket_salt = 0x6d2535a1;
    }

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
        int child_fd = fd_preserve_only(sockets[1]);
        if (child_fd < 0)
            _exit(EXIT_FAILURE);
        resolver_child_main(child_fd, nameservers, search, mode,
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

    /* Protect restart flag check with mutex to prevent race conditions */
    pthread_mutex_lock(&resolver_restart_lock);
    int restarting = resolver_restart_in_progress;
    pthread_mutex_unlock(&resolver_restart_lock);

    if (restarting) {
        if (resolver_pending_restart_list != NULL)
            resolver_free_pending_list(resolver_pending_restart_list, 1);
        resolver_pending_restart_list = resolver_detach_pending_queries();
    } else {
        resolver_cleanup_pending_queries();
    }

    ipc_crypto_state_clear(&resolver_ipc_crypto);
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

    struct ResolvQuery *handle = calloc(1, sizeof(*handle));
    if (handle == NULL) {
        err("Failed to allocate memory for DNS query callback data.");
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }

    handle->client_cb = client_cb;
    handle->client_free_cb = client_free_cb;
    handle->client_cb_data = client_cb_data;
    handle->next_client = NULL;

    int requested_mode = mode != RESOLV_MODE_DEFAULT ? mode : default_resolv_mode;
    uint32_t host_hash = resolver_hostname_hash(hostname, hostname_len, requested_mode);

    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolverPending *pending = resolver_find_pending_host(hostname, hostname_len,
            requested_mode, host_hash);
    if (pending != NULL) {
        handle->pending = pending;
        handle->next_client = pending->clients;
        pending->clients = handle;
        pthread_mutex_unlock(&resolver_queries_lock);
        return handle;
    }
    pthread_mutex_unlock(&resolver_queries_lock);

    struct ResolverPending *new_pending = calloc(1, sizeof(*new_pending));
    if (new_pending == NULL) {
        err("Failed to allocate resolver pending entry");
        free(handle);
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }

    new_pending->hostname = malloc(hostname_len + 1);
    if (new_pending->hostname == NULL) {
        free(new_pending);
        free(handle);
        err("malloc failed while queuing DNS query");
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        return NULL;
    }
    memcpy(new_pending->hostname, hostname, hostname_len);
    new_pending->hostname[hostname_len] = '\0';

    new_pending->hostname_len = hostname_len;
    new_pending->resolv_mode = requested_mode;
    new_pending->host_hash = host_hash;
    new_pending->id = resolver_next_query_prng();
    if (new_pending->id == 0)
        new_pending->id = resolver_next_query_prng();

    handle->pending = new_pending;
    handle->next_client = NULL;
    new_pending->clients = handle;

    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolverPending *race = resolver_find_pending_host(hostname, hostname_len,
            requested_mode, host_hash);
    if (race != NULL) {
        free(new_pending->hostname);
        free(new_pending);
        handle->pending = race;
        handle->next_client = race->clients;
        race->clients = handle;
        pthread_mutex_unlock(&resolver_queries_lock);
        return handle;
    }

    resolver_attach_query(new_pending);
    pthread_mutex_unlock(&resolver_queries_lock);

    if (resolver_emit_query(new_pending) < 0) {
        pthread_mutex_lock(&resolver_queries_lock);
        resolver_remove_pending(new_pending);
        pthread_mutex_unlock(&resolver_queries_lock);
        if (client_cb != NULL)
            client_cb(NULL, client_cb_data);
        if (client_free_cb != NULL)
            client_free_cb(client_cb_data);
        free(handle);
        free(new_pending->hostname);
        free(new_pending);
        return NULL;
    }

    return handle;
}

void
resolv_cancel(struct ResolvQuery *handle) {
    if (handle == NULL)
        return;

    struct ResolverPending *pending = handle->pending;
    if (pending == NULL) {
        if (handle->client_free_cb != NULL)
            handle->client_free_cb(handle->client_cb_data);
        free(handle);
        return;
    }

    int send_cancel = 0;
    uint32_t cancel_id = 0;
    int found = 0;

    pthread_mutex_lock(&resolver_queries_lock);

    /* Check if the clients list has already been detached by
     * resolver_take_query(). If so, the result is being processed
     * and our handle will be freed by resolver_handle_result(). */
    if (pending->clients != NULL) {
        struct ResolvQuery **iter = &pending->clients;
        while (*iter != NULL && *iter != handle)
            iter = &(*iter)->next_client;

        if (*iter == handle) {
            found = 1;
            *iter = handle->next_client;
            if (pending->clients == NULL) {
                resolver_remove_pending(pending);
                send_cancel = 1;
                cancel_id = pending->id;
            }
        }
    }
    pthread_mutex_unlock(&resolver_queries_lock);

    /* Only free our handle if we successfully removed it from the list.
     * If pending->clients was NULL, the handle is owned by
     * resolver_handle_result() and will be freed there. */
    if (found) {
        if (handle->client_free_cb != NULL)
            handle->client_free_cb(handle->client_cb_data);
        free(handle);
    }

    if (send_cancel) {
        resolver_send_message(RESOLVER_CMD_CANCEL, cancel_id, NULL, 0);
        free(pending->hostname);
        free(pending);
    }
}

static int
resolver_send_message(uint32_t type, uint32_t id, const void *payload, size_t payload_len) {
    if (resolver_sock < 0)
        return -1;

    if (payload_len > RESOLVER_IPC_MAX_PAYLOAD) {
        err("resolver payload too large: %zu", payload_len);
        return -1;
    }

    uint8_t plain[sizeof(struct resolver_ipc_header) + RESOLVER_IPC_MAX_PAYLOAD];
    struct resolver_ipc_header header;

    header.type = htonl(type);
    header.id = htonl(id);
    header.payload_len = htonl((uint32_t)payload_len);

    memcpy(plain, &header, sizeof(header));
    if (payload_len > 0 && payload != NULL)
        memcpy(plain + sizeof(header), payload, payload_len);

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (ipc_crypto_seal(&resolver_ipc_crypto, plain, sizeof(header) + payload_len,
            &frame, &frame_len) < 0) {
        err("resolver crypto seal failed");
        return -1;
    }

    ssize_t written = send(resolver_sock, frame, frame_len, 0);
    free(frame);
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
        uint8_t buffer[RESOLVER_IPC_MAX_FRAME];
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

        uint8_t *plain = NULL;
        size_t plain_len = 0;
        if (ipc_crypto_open(&resolver_ipc_crypto, buffer, (size_t)len,
                    RESOLVER_IPC_MAX_PAYLOAD, &plain, &plain_len) < 0)
            continue;

        resolver_process_datagram(plain, (ssize_t)plain_len);
        free(plain);
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
        case RESOLVER_CMD_CRASH:
            resolver_handle_crash_notice(payload, payload_len);
            break;
        default:
            break;
    }
}

static void
resolver_handle_crash_notice(const uint8_t *payload, size_t payload_len) {
    if (payload == NULL) {
        err("resolver child crash reported with NULL payload");
        return;
    }

    size_t copy_len = payload_len;
    if (copy_len > RESOLVER_IPC_MAX_PAYLOAD)
        copy_len = RESOLVER_IPC_MAX_PAYLOAD;

    char message[RESOLVER_IPC_MAX_PAYLOAD + 1];
    if (copy_len > 0)
        memcpy(message, payload, copy_len);
    message[copy_len] = '\0';

    if (copy_len == 0) {
        err("resolver child crash reported with empty payload");
        return;
    }

    err("%s", message);
}

static void
resolver_handle_result(uint32_t id, const uint8_t *payload, size_t payload_len) {
    struct ResolverPending *pending = resolver_take_query(id);
    if (pending == NULL)
        return;

    /* Extract the detached clients list from temporary storage.
     * resolver_take_query() stored it in next_id to safely transfer
     * ownership of the list to us without holding the mutex. */
    struct ResolvQuery *clients = (struct ResolvQuery *)pending->next_id;
    pending->next_id = NULL;

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

    /* Process the detached clients list. This is now safe from concurrent
     * modification by resolv_cancel() because:
     * 1. The pending is no longer in the hash tables (removed by resolver_take_query)
     * 2. pending->clients was set to NULL atomically while holding the mutex
     * 3. We're iterating our private copy of the list
     * Any concurrent resolv_cancel() will find pending->clients == NULL and
     * will not attempt to modify this list. */
    struct ResolvQuery *client = clients;
    while (client != NULL) {
        struct ResolvQuery *next_client = client->next_client;
        if (client->client_cb != NULL)
            client->client_cb((status == 0) ? address : NULL, client->client_cb_data);
        if (client->client_free_cb != NULL)
            client->client_free_cb(client->client_cb_data);
        free(client);
        client = next_client;
    }

    if (address != NULL)
        free(address);

    free(pending->hostname);
    free(pending);
}

static int
resolver_emit_query(struct ResolverPending *pending) {
    if (pending == NULL || resolver_sock < 0)
        return -1;

    size_t hostname_len = pending->hostname_len;
    if (hostname_len == 0 || hostname_len > RESOLVER_MAX_HOSTNAME_LEN)
        return -1;

    uint8_t payload[sizeof(uint32_t) + RESOLVER_MAX_HOSTNAME_LEN];
    uint32_t mode_net = htonl((uint32_t)pending->resolv_mode);
    memcpy(payload, &mode_net, sizeof(mode_net));
    memcpy(payload + sizeof(mode_net), pending->hostname, hostname_len);

    return resolver_send_message(RESOLVER_CMD_QUERY, pending->id,
            payload, sizeof(mode_net) + hostname_len);
}


static void
resolver_attach_query(struct ResolverPending *pending) {
    if (pending == NULL)
        return;

    size_t id_bucket = resolver_query_bucket_index(pending->id);
    pending->next_id = resolver_queries[id_bucket];
    resolver_queries[id_bucket] = pending;

    size_t host_bucket = resolver_host_bucket_index(pending->host_hash);
    pending->next_host = resolver_hosts[host_bucket];
    resolver_hosts[host_bucket] = pending;
}

static struct ResolverPending *
resolver_take_query(uint32_t id) {
    pthread_mutex_lock(&resolver_queries_lock);
    size_t bucket = resolver_query_bucket_index(id);
    struct ResolverPending **iter = &resolver_queries[bucket];
    while (*iter != NULL) {
        if ((*iter)->id == id) {
            struct ResolverPending *found = *iter;
            *iter = found->next_id;

            size_t host_bucket = resolver_host_bucket_index(found->host_hash);
            struct ResolverPending **host_iter = &resolver_hosts[host_bucket];
            while (*host_iter != NULL) {
                if (*host_iter == found) {
                    *host_iter = found->next_host;
                    break;
                }
                host_iter = &(*host_iter)->next_host;
            }

            /* Atomically detach the clients list to prevent concurrent
             * modification by resolv_cancel(). We temporarily store the
             * clients list in next_id field (which we're clearing anyway)
             * so the caller can retrieve it safely. This prevents use-after-free
             * if a client calls resolv_cancel() while we process callbacks. */
            found->next_id = (struct ResolverPending *)found->clients;
            found->next_host = NULL;
            found->clients = NULL;

            pthread_mutex_unlock(&resolver_queries_lock);
            return found;
        }
        iter = &(*iter)->next_id;
    }
    pthread_mutex_unlock(&resolver_queries_lock);
    return NULL;
}

static void
resolver_remove_pending(struct ResolverPending *pending) {
    if (pending == NULL)
        return;

    size_t bucket = resolver_query_bucket_index(pending->id);
    struct ResolverPending **iter = &resolver_queries[bucket];
    while (*iter != NULL) {
        if (*iter == pending) {
            *iter = pending->next_id;
            break;
        }
        iter = &(*iter)->next_id;
    }

    size_t host_bucket = resolver_host_bucket_index(pending->host_hash);
    iter = &resolver_hosts[host_bucket];
    while (*iter != NULL) {
        if (*iter == pending) {
            *iter = pending->next_host;
            break;
        }
        iter = &(*iter)->next_host;
    }

    pending->next_id = NULL;
    pending->next_host = NULL;
}

static struct ResolverPending *
resolver_detach_pending_queries(void) {
    pthread_mutex_lock(&resolver_queries_lock);
    struct ResolverPending *pending_list = NULL;
    for (size_t i = 0; i < RESOLVER_HOST_BUCKETS; i++) {
        struct ResolverPending *iter = resolver_hosts[i];
        resolver_hosts[i] = NULL;
        while (iter != NULL) {
            struct ResolverPending *next = iter->next_host;
            iter->next_host = pending_list;
            pending_list = iter;
            iter = next;
        }
    }
    memset(resolver_queries, 0, sizeof(resolver_queries));
    pthread_mutex_unlock(&resolver_queries_lock);

    return pending_list;
}

static void
resolver_free_pending_list(struct ResolverPending *pending_list, int notify_clients) {
    while (pending_list != NULL) {
        struct ResolverPending *next_pending = pending_list->next_host;
        struct ResolvQuery *client = pending_list->clients;
        while (client != NULL) {
            struct ResolvQuery *next_client = client->next_client;
            if (notify_clients && client->client_cb != NULL)
                client->client_cb(NULL, client->client_cb_data);
            if (client->client_free_cb != NULL)
                client->client_free_cb(client->client_cb_data);
            free(client);
            client = next_client;
        }
        free(pending_list->hostname);
        free(pending_list);
        pending_list = next_pending;
    }
}

static void
resolver_cleanup_pending_queries(void) {
    struct ResolverPending *pending_list = resolver_detach_pending_queries();
    resolver_free_pending_list(pending_list, 1);
}

static void
resolver_resubmit_pending_queries(void) {
    struct ResolverPending *pending_list = resolver_pending_restart_list;
    resolver_pending_restart_list = NULL;

    while (pending_list != NULL) {
        struct ResolverPending *next = pending_list->next_host;
        pending_list->next_host = NULL;
        pending_list->next_id = NULL;

        pthread_mutex_lock(&resolver_queries_lock);
        resolver_attach_query(pending_list);
        pthread_mutex_unlock(&resolver_queries_lock);

        if (resolver_emit_query(pending_list) < 0) {
            pthread_mutex_lock(&resolver_queries_lock);
            resolver_remove_pending(pending_list);
            pthread_mutex_unlock(&resolver_queries_lock);
            resolver_free_pending_list(pending_list, 1);
        }

        pending_list = next;
    }
}

static void
resolver_fail_pending_restart_list(void) {
    if (resolver_pending_restart_list == NULL)
        return;

    resolver_free_pending_list(resolver_pending_restart_list, 1);
    resolver_pending_restart_list = NULL;
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

    if (rc == 0)
        resolver_resubmit_pending_queries();
    else
        resolver_fail_pending_restart_list();

    pthread_mutex_lock(&resolver_restart_lock);
    resolver_restart_in_progress = 0;
    pthread_mutex_unlock(&resolver_restart_lock);

    return rc;
}

static void
resolver_child_crash_handler(int signum) {
    /* SECURITY: Only async-signal-safe operations allowed in signal handlers.
     * Per POSIX signal-safety(7), we can only use: write(), _exit(), and
     * a few other specific functions. We MUST NOT use:
     * - htonl() or other functions that might use locks
     * - writev() over IPC (removed - could deadlock or corrupt state)
     * - malloc/free or any function that manipulates shared state
     * The signal handler will be reset by SA_RESETHAND, so after this
     * returns, the signal will terminate the process. */
    const char msg_prefix[] = "resolver child crashed with signal ";
    const size_t msg_prefix_len = sizeof(msg_prefix) - 1;
    const char *signame = "UNKNOWN";
    size_t signame_len = sizeof("UNKNOWN") - 1;

    switch (signum) {
        case SIGSEGV:
            signame = "SIGSEGV (segmentation fault)";
            signame_len = sizeof("SIGSEGV (segmentation fault)") - 1;
            break;
        case SIGBUS:
            signame = "SIGBUS (bus error)";
            signame_len = sizeof("SIGBUS (bus error)") - 1;
            break;
        case SIGABRT:
            signame = "SIGABRT (abort)";
            signame_len = sizeof("SIGABRT (abort)") - 1;
            break;
        case SIGILL:
            signame = "SIGILL (illegal instruction)";
            signame_len = sizeof("SIGILL (illegal instruction)") - 1;
            break;
        case SIGFPE:
            signame = "SIGFPE (floating point exception)";
            signame_len = sizeof("SIGFPE (floating point exception)") - 1;
            break;
        default:
            break;
    }

    /* Write to stderr - write() is async-signal-safe */
    ssize_t unused_write;
    unused_write = write(STDERR_FILENO, msg_prefix, msg_prefix_len);
    (void)unused_write;
    unused_write = write(STDERR_FILENO, signame, signame_len);
    (void)unused_write;
    unused_write = write(STDERR_FILENO, "\n", 1);
    (void)unused_write;

    /* Do NOT attempt IPC communication from signal handler:
     * - Removed htonl() call (not guaranteed async-signal-safe)
     * - Removed writev() to child_sock (could deadlock or corrupt IPC state)
     * - Parent will detect child crash via SIGCHLD/waitpid()
     * This is safer and follows signal safety best practices. */
}

static void __attribute__((noreturn))
resolver_child_exit(int status) {
    ipc_crypto_state_clear(&resolver_ipc_crypto);
    _exit(status);
}

static void
resolver_child_main(int sockfd, char **nameservers, char **search_domains, int default_mode, int dnssec_mode) {
    child_sock = sockfd;
    child_default_resolv_mode = default_mode;
    ipc_crypto_channel_set_role(&resolver_ipc_crypto, IPC_CRYPTO_ROLE_CHILD);

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
        resolver_child_exit(EXIT_FAILURE);
    }

    resolver_child_setup_dns(child_loop, nameservers, search_domains,
            default_mode, dnssec_mode);

#ifdef __OpenBSD__
    /* Allow rpath so OpenSSL can read trusted CA bundles for DoT verification. */
    if (pledge("stdio rpath inet dns unix", NULL) == -1) {
        perror("resolver pledge");
        resolver_child_exit(EXIT_FAILURE);
    }
#endif

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

    resolver_child_exit(EXIT_SUCCESS);
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

    if (search_domains != NULL && search_domains[0] != NULL) {
        int ndomains = 0;
        while (search_domains[ndomains] != NULL)
            ndomains++;
        options.domains = search_domains;
        options.ndomains = ndomains;
        optmask |= ARES_OPT_DOMAINS;
    }

    resolver_child_free_dot_servers();
    char **processed_nameservers = NULL;
    if (resolver_child_process_nameservers(nameservers, &processed_nameservers) < 0) {
        err("resolver child: failed to process nameserver list");
        resolver_child_exit(EXIT_FAILURE);
    }

    if (child_dot_server_count > 0)
        options.flags |= ARES_FLAG_USEVC;

    if (options.flags != 0)
        optmask |= ARES_OPT_FLAGS;

    int status = ares_init_options(&child_channel, options_ptr, optmask);
    if (status != ARES_SUCCESS) {
        err("resolver child: ares_init failed: %s", ares_strerror(status));
        resolver_child_exit(EXIT_FAILURE);
    }

    if (processed_nameservers != NULL && processed_nameservers[0] != NULL) {
        char *csv = resolver_child_nameservers_csv(processed_nameservers);
        if (csv == NULL) {
            resolver_child_free_processed_nameservers(processed_nameservers);
            err("resolver child: failed to allocate nameserver list");
            resolver_child_exit(EXIT_FAILURE);
        }
        status = ares_set_servers_csv(child_channel, csv);
        free(csv);
        resolver_child_free_processed_nameservers(processed_nameservers);
        if (status != ARES_SUCCESS) {
            err("resolver child: ares_set_servers_csv failed: %s", ares_strerror(status));
            resolver_child_exit(EXIT_FAILURE);
        }
    } else {
        resolver_child_free_processed_nameservers(processed_nameservers);
    }

    if (child_dot_server_count > 0) {
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        ares_set_socket_functions(child_channel, &resolver_child_dot_socket_functions, NULL);
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
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

    while (child_dot_socket_list != NULL)
        resolver_child_dot_socket_detach(child_dot_socket_list->fd);

    resolver_child_free_dot_ssl_ctx();
    resolver_child_free_dot_servers();

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
        uint8_t buffer[RESOLVER_IPC_MAX_FRAME];
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

        uint8_t *plain = NULL;
        size_t plain_len = 0;
        if (ipc_crypto_open(&resolver_ipc_crypto, buffer, (size_t)len,
                    RESOLVER_IPC_MAX_PAYLOAD, &plain, &plain_len) < 0)
            continue;

        if (plain_len < sizeof(struct resolver_ipc_header)) {
            free(plain);
            continue;
        }

        struct resolver_ipc_header header;
        memcpy(&header, plain, sizeof(header));

        uint32_t type = ntohl(header.type);
        uint32_t id = ntohl(header.id);
        uint32_t payload_len = ntohl(header.payload_len);

        if (payload_len > RESOLVER_IPC_MAX_PAYLOAD) {
            free(plain);
            continue;
        }

        if ((ssize_t)payload_len != (ssize_t)plain_len - (ssize_t)sizeof(header)) {
            free(plain);
            continue;
        }

        const uint8_t *payload = plain + sizeof(header);

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

        free(plain);
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

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (ipc_crypto_seal(&resolver_ipc_crypto, buffer,
            sizeof(header) + offset + (status == 0 ? addr_len : 0),
            &frame, &frame_len) < 0) {
        err("resolver child: crypto seal failed");
        return;
    }

    if (send(child_sock, frame, frame_len, 0) < 0) {
        err("resolver child send failed: %s (errno=%d)", strerror(errno), errno);
        if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN) {
            notice("resolver child: parent socket dead, exiting");
            if (child_loop != NULL)
                ev_break(child_loop, EVBREAK_ALL);
        }
    }
    free(frame);
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

    struct ResolverChildDotSocket *sock = resolver_child_dot_socket_get(socket_fd);
    if (sock != NULL && sock->server != NULL) {
        sock->base_events = events;
        if (!sock->handshake_complete && events != 0) {
            events = EV_READ | EV_WRITE;
            sock->forcing_events = 1;
        } else if (sock->handshake_complete) {
            sock->forcing_events = 0;
        }
    }

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
resolver_child_free_processed_nameservers(char **list) {
    if (list == NULL)
        return;

    for (size_t i = 0; list[i] != NULL; i++) {
        free(list[i]);
        list[i] = NULL;
    }

    free(list);
}

static int
resolver_child_append_processed_nameserver(char ***list_ptr, size_t *count_ptr, const char *entry) {
    if (entry == NULL)
        return 0;

    char **list = *list_ptr;
    size_t count = *count_ptr;
    char **tmp = realloc(list, (count + 2) * sizeof(char *));
    if (tmp == NULL)
        return -1;

    list = tmp;
    list[count] = strdup(entry);
    if (list[count] == NULL)
        return -1;
    list[count + 1] = NULL;

    *list_ptr = list;
    *count_ptr = count + 1;
    return 0;
}

static int
resolver_child_process_nameservers(char **nameservers, char ***processed_out) {
    *processed_out = NULL;

    if (nameservers == NULL)
        return 0;

    size_t count = 0;
    char **processed = NULL;

    for (size_t i = 0; nameservers[i] != NULL; i++) {
        const char *entry = nameservers[i];
        if (strncasecmp(entry, "dot://", 6) == 0) {
            const char *target = entry + 6;
            char *converted = NULL;
            if (resolver_child_handle_dot_server(target, &converted) < 0) {
                resolver_child_free_processed_nameservers(processed);
                return -1;
            }
            if (converted == NULL)
                continue;
            if (resolver_child_append_processed_nameserver(&processed, &count, converted) < 0) {
                free(converted);
                resolver_child_free_processed_nameservers(processed);
                return -1;
            }
            free(converted);
        } else {
            if (resolver_child_append_processed_nameserver(&processed, &count, entry) < 0) {
                resolver_child_free_processed_nameservers(processed);
                return -1;
            }
        }
    }

    *processed_out = processed;
    return 0;
}

static int
resolver_child_handle_dot_server(const char *target, char **converted) {
    if (target == NULL || converted == NULL)
        return -1;

    struct Address *addr = new_address(target);
    if (addr == NULL)
        return -1;

    *converted = NULL;

    uint16_t port = address_port(addr);
    if (port == 0)
        port = 853;
    address_set_port(addr, port);

    struct ResolverDotServer server;
    memset(&server, 0, sizeof(server));

    if (address_is_sockaddr(addr)) {
        const struct sockaddr *sa = address_sa(addr);
        socklen_t len = address_sa_len(addr);
        if (sa == NULL || len == 0) {
            free(addr);
            return -1;
        }
        if (len > (socklen_t)sizeof(server.addr)) {
            free(addr);
            return -1;
        }
        memcpy(&server.addr, sa, len);
        server.addr_len = len;
        server.sni_hostname = NULL;
        server.verify_certificate = 0;
    } else if (address_is_hostname(addr)) {
        const char *hostname = address_hostname(addr);
        if (hostname == NULL) {
            free(addr);
            return -1;
        }
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

#ifdef HAVE_RESOLV_H
        (void)res_init();
#endif

        struct addrinfo *results = NULL;
        int rc = getaddrinfo(hostname, port_str, &hints, &results);
        if (rc != 0) {
            warn("resolver child: unable to resolve DoT nameserver '%s': %s; skipping this entry",
                    hostname, gai_strerror(rc));
            free(addr);
            return 0;
        }

        struct addrinfo *selected = results;
        while (selected != NULL && selected->ai_addrlen > (socklen_t)sizeof(server.addr))
            selected = selected->ai_next;
        if (selected == NULL) {
            freeaddrinfo(results);
            free(addr);
            return -1;
        }

        memcpy(&server.addr, selected->ai_addr, selected->ai_addrlen);
        server.addr_len = (socklen_t)selected->ai_addrlen;
        server.sni_hostname = strdup(hostname);
        server.verify_certificate = 1;
        freeaddrinfo(results);
        if (server.sni_hostname == NULL) {
            free(addr);
            return -1;
        }
    } else {
        free(addr);
        return -1;
    }

    free(addr);

    if (child_dot_server_count == child_dot_server_capacity) {
        size_t new_cap = child_dot_server_capacity == 0 ? 4 : child_dot_server_capacity * 2;
        struct ResolverDotServer *tmp = realloc(child_dot_servers, new_cap * sizeof(*tmp));
        if (tmp == NULL) {
            free(server.sni_hostname);
            return -1;
        }
        child_dot_servers = tmp;
        child_dot_server_capacity = new_cap;
    }

    child_dot_servers[child_dot_server_count] = server;
    struct ResolverDotServer *slot = &child_dot_servers[child_dot_server_count];
    child_dot_server_count++;

    char buffer[ADDRESS_BUFFER_SIZE];
    display_sockaddr(&slot->addr, slot->addr_len, buffer, sizeof(buffer));
    *converted = strdup(buffer);
    if (*converted == NULL)
        return -1;

    return 0;
}

static void
resolver_child_free_dot_servers(void) {
    if (child_dot_servers == NULL) {
        child_dot_server_count = 0;
        child_dot_server_capacity = 0;
        return;
    }

    for (size_t i = 0; i < child_dot_server_count; i++) {
        free(child_dot_servers[i].sni_hostname);
        child_dot_servers[i].sni_hostname = NULL;
        child_dot_servers[i].addr_len = 0;
    }

    free(child_dot_servers);
    child_dot_servers = NULL;
    child_dot_server_count = 0;
    child_dot_server_capacity = 0;
}

static struct ResolverDotServer *
resolver_child_find_dot_server_sa(const struct sockaddr *addr, ares_socklen_t addrlen) {
    if (addr == NULL || addrlen == 0)
        return NULL;

    for (size_t i = 0; i < child_dot_server_count; i++) {
        if (resolver_child_sockaddr_equal((const struct sockaddr *)&child_dot_servers[i].addr,
                    child_dot_servers[i].addr_len, addr, addrlen))
            return &child_dot_servers[i];
    }

    return NULL;
}

static int
resolver_child_sockaddr_equal(const struct sockaddr *a, ares_socklen_t alen,
        const struct sockaddr *b, ares_socklen_t blen) {
    if (a == NULL || b == NULL)
        return 0;

    if (a->sa_family != b->sa_family)
        return 0;

    switch (a->sa_family) {
        case AF_INET: {
            if (alen < (ares_socklen_t)sizeof(struct sockaddr_in) ||
                    blen < (ares_socklen_t)sizeof(struct sockaddr_in))
                return 0;
            const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
            const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
            return a4->sin_port == b4->sin_port &&
                    memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr)) == 0;
        }
        case AF_INET6: {
            if (alen < (ares_socklen_t)sizeof(struct sockaddr_in6) ||
                    blen < (ares_socklen_t)sizeof(struct sockaddr_in6))
                return 0;
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
            return a6->sin6_port == b6->sin6_port &&
                    memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
        }
        default:
            if (alen != blen)
                return 0;
            return memcmp(a, b, alen) == 0;
    }
}

static int
resolver_child_init_dot_ssl_ctx(void) {
    if (child_dot_ssl_ctx != NULL)
        return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#else
    if (OPENSSL_init_ssl(0, NULL) != 1)
        return -1;
#endif

    child_dot_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (child_dot_ssl_ctx == NULL)
        return -1;

    if (SSL_CTX_set_default_verify_paths(child_dot_ssl_ctx) != 1) {
        SSL_CTX_free(child_dot_ssl_ctx);
        child_dot_ssl_ctx = NULL;
        return -1;
    }

    const char *default_cafile = X509_get_default_cert_file();
    if (default_cafile != NULL) {
        if (SSL_CTX_load_verify_locations(child_dot_ssl_ctx, default_cafile, NULL) != 1)
            debug_log("resolver child: failed to load default CA file %s", default_cafile);
    }

    const char *default_cadir = X509_get_default_cert_dir();
    if (default_cadir != NULL) {
        if (SSL_CTX_load_verify_locations(child_dot_ssl_ctx, NULL, default_cadir) != 1)
            debug_log("resolver child: failed to load default CA dir %s", default_cadir);
    }

    for (size_t i = 0; resolver_cafile_fallbacks[i] != NULL; i++) {
        if (SSL_CTX_load_verify_locations(child_dot_ssl_ctx, resolver_cafile_fallbacks[i], NULL) == 1)
            break;
    }

    for (size_t i = 0; resolver_cadir_fallbacks[i] != NULL; i++) {
        if (SSL_CTX_load_verify_locations(child_dot_ssl_ctx, NULL, resolver_cadir_fallbacks[i]) == 1)
            break;
    }

    SSL_CTX_set_verify(child_dot_ssl_ctx, SSL_VERIFY_PEER, NULL);
    return 0;
}

static void
resolver_child_free_dot_ssl_ctx(void) {
    if (child_dot_ssl_ctx != NULL) {
        SSL_CTX_free(child_dot_ssl_ctx);
        child_dot_ssl_ctx = NULL;
    }
}

static struct ResolverChildDotSocket *
resolver_child_dot_socket_get(ares_socket_t fd) {
    struct ResolverChildDotSocket *iter = child_dot_socket_list;
    while (iter != NULL) {
        if (iter->fd == fd)
            return iter;
        iter = iter->next;
    }
    return NULL;
}

static void
resolver_child_dot_socket_detach(ares_socket_t fd) {
    struct ResolverChildDotSocket **iter = &child_dot_socket_list;
    while (*iter != NULL) {
        if ((*iter)->fd == fd) {
            struct ResolverChildDotSocket *cur = *iter;
            *iter = cur->next;
            if (cur->ssl != NULL)
                SSL_free(cur->ssl);
            free(cur);
            break;
        }
        iter = &(*iter)->next;
    }
}

static int
resolver_child_dot_socket_attach(ares_socket_t fd, struct ResolverDotServer *server) {
    if (server == NULL)
        return 0;

    if (resolver_child_init_dot_ssl_ctx() < 0)
        return -1;

    struct ResolverChildDotSocket *sock = resolver_child_dot_socket_get(fd);
    if (sock == NULL) {
        sock = calloc(1, sizeof(*sock));
        if (sock == NULL)
            return -1;
        sock->fd = fd;
        sock->next = child_dot_socket_list;
        child_dot_socket_list = sock;
    } else if (sock->ssl != NULL) {
        SSL_free(sock->ssl);
        sock->ssl = NULL;
    }

    sock->server = server;
    sock->handshake_complete = 0;
    sock->forcing_events = 0;
    sock->base_events = 0;
    sock->failed = 0;

    sock->ssl = SSL_new(child_dot_ssl_ctx);
    if (sock->ssl == NULL)
        return -1;

    SSL_set_connect_state(sock->ssl);
    if (SSL_set_fd(sock->ssl, fd) != 1)
        goto error;

    if (server->sni_hostname != NULL && server->verify_certificate) {
        if (SSL_set_tlsext_host_name(sock->ssl, server->sni_hostname) != 1)
            goto error;
        X509_VERIFY_PARAM *param = SSL_get0_param(sock->ssl);
        if (param != NULL) {
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_host(param, server->sni_hostname, 0) != 1)
                goto error;
        }
        SSL_set_verify(sock->ssl, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_set_verify(sock->ssl, SSL_VERIFY_NONE, NULL);
    }

    return 0;

error:
    sock->failed = 1;
    if (sock->ssl != NULL) {
        SSL_free(sock->ssl);
        sock->ssl = NULL;
    }
    resolver_child_dot_socket_detach(fd);
    return -1;
}

static int
resolver_child_dot_ensure_handshake(struct ResolverChildDotSocket *sock) {
    if (sock == NULL || sock->ssl == NULL)
        return -1;

    if (sock->failed) {
        errno = ECONNABORTED;
        return -1;
    }

    if (sock->handshake_complete)
        return 0;

    int ret = SSL_do_handshake(sock->ssl);
    if (ret == 1) {
        sock->handshake_complete = 1;
        if (sock->forcing_events) {
            resolver_child_watch_fd(child_loop, sock->fd, sock->base_events);
            sock->forcing_events = 0;
        }
        return 0;
    }

    int errcode = SSL_get_error(sock->ssl, ret);
    if (errcode == SSL_ERROR_WANT_READ || errcode == SSL_ERROR_WANT_WRITE) {
        errno = EWOULDBLOCK;
        return -1;
    }

    if (errcode == SSL_ERROR_SSL) {
        long verify_err = SSL_get_verify_result(sock->ssl);
        if (verify_err != X509_V_OK) {
            const char *hostname = (sock->server != NULL && sock->server->sni_hostname != NULL) ?
                    sock->server->sni_hostname : "(ip)";
            warn("resolver child: DoT certificate verification failed for %s: %s",
                    hostname, X509_verify_cert_error_string(verify_err));
        }
    }

    unsigned long ssl_err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(ssl_err, buf, sizeof(buf));
    err("resolver child: DoT handshake failed: %s", buf);
    sock->failed = 1;
    errno = ECONNABORTED;
    return -1;
}

static ares_socket_t
resolver_child_dot_asocket(int domain, int type, int protocol, void *user_data __attribute__((unused))) {
    return socket(domain, type, protocol);
}

static int
resolver_child_dot_aclose(ares_socket_t fd, void *user_data __attribute__((unused))) {
    resolver_child_dot_socket_detach(fd);
    return close(fd);
}

static int
resolver_child_dot_aconnect(ares_socket_t fd, const struct sockaddr *address, ares_socklen_t addrlen, void *user_data __attribute__((unused))) {
    struct ResolverDotServer *server = resolver_child_find_dot_server_sa(address, addrlen);
    if (server != NULL) {
        if (resolver_child_dot_socket_attach(fd, server) < 0)
            return -1;
    }

    return connect(fd, address, addrlen);
}

static ares_ssize_t
resolver_child_dot_arecvfrom(ares_socket_t fd, void *buffer, size_t len, int flags,
        struct sockaddr *addr, ares_socklen_t *addrlen, void *user_data __attribute__((unused))) {
    struct ResolverChildDotSocket *sock = resolver_child_dot_socket_get(fd);
    if (sock == NULL || sock->server == NULL)
        return recvfrom(fd, buffer, len, flags, addr, addrlen);

    if (!sock->handshake_complete) {
        if (resolver_child_dot_ensure_handshake(sock) < 0)
            return -1;
    }

    int ret = SSL_read(sock->ssl, buffer, (int)len);
    if (ret > 0)
        return ret;

    int errcode = SSL_get_error(sock->ssl, ret);
    if (errcode == SSL_ERROR_WANT_READ || errcode == SSL_ERROR_WANT_WRITE) {
        errno = EWOULDBLOCK;
        return -1;
    }

    unsigned long ssl_err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(ssl_err, buf, sizeof(buf));
    err("resolver child: DoT read failed: %s", buf);
    sock->failed = 1;
    errno = ECONNABORTED;
    return -1;
}

static ares_ssize_t
resolver_child_dot_asendv(ares_socket_t fd, const struct iovec *iov, int iovcnt, void *user_data __attribute__((unused))) {
    struct ResolverChildDotSocket *sock = resolver_child_dot_socket_get(fd);
    if (sock == NULL || sock->server == NULL)
        return writev(fd, iov, iovcnt);

    if (!sock->handshake_complete) {
        if (resolver_child_dot_ensure_handshake(sock) < 0)
            return -1;
    }

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++)
        total += iov[i].iov_len;

    if (total == 0)
        return 0;

    uint8_t stack_buf[512];
    uint8_t *buf = stack_buf;
    int use_heap = 0;
    if (total > sizeof(stack_buf)) {
        buf = malloc(total);
        if (buf == NULL)
            return -1;
        use_heap = 1;
    }

    size_t offset = 0;
    for (int i = 0; i < iovcnt; i++) {
        memcpy(buf + offset, iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len;
    }

    int ret = SSL_write(sock->ssl, buf, (int)total);
    if (use_heap)
        free(buf);

    if (ret > 0)
        return ret;

    int errcode = SSL_get_error(sock->ssl, ret);
    if (errcode == SSL_ERROR_WANT_READ || errcode == SSL_ERROR_WANT_WRITE) {
        errno = EWOULDBLOCK;
        return -1;
    }

    unsigned long ssl_err = ERR_get_error();
    char errbuf[256];
    ERR_error_string_n(ssl_err, errbuf, sizeof(errbuf));
    err("resolver child: DoT write failed: %s", errbuf);
    sock->failed = 1;
    errno = ECONNABORTED;
    return -1;
}

static const struct ares_socket_functions resolver_child_dot_socket_functions = {
    .asocket = resolver_child_dot_asocket,
    .aclose = resolver_child_dot_aclose,
    .aconnect = resolver_child_dot_aconnect,
    .arecvfrom = resolver_child_dot_arecvfrom,
    .asendv = resolver_child_dot_asendv,
};

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

    if (query->cancelled) {
        debug_log("resolver child: query_id=%u cancelled, ignoring response family=%d status=%d",
                query->id, family, status);
    } else if (status == ARES_SUCCESS && result != NULL) {
        for (struct ares_addrinfo_node *node = result->nodes; node != NULL; node = node->ai_next) {
            if (node->ai_family != family || node->ai_addr == NULL)
                continue;

            struct Address *response = new_address_sa(node->ai_addr, (socklen_t)node->ai_addrlen);
            if (response == NULL) {
                err("resolver child: failed to allocate memory for DNS query result address");
                continue;
            }

            /* Limit DNS responses to prevent memory exhaustion from malicious servers */
            if (query->response_count >= RESOLVER_MAX_DNS_RESPONSES) {
                err("resolver child: DNS response limit (%zu) reached, ignoring additional addresses",
                    (size_t)RESOLVER_MAX_DNS_RESPONSES);
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
