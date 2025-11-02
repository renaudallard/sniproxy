/*
 * Copyright (c) 2024, Renaud Allard
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <ev.h>

#include "address.h"
#include "listener.h"
#include "logger.h"
#include "fd_util.h"
#include "quic_listener.h"

#define QUIC_MAX_DATAGRAM 65536
#define QUIC_SESSION_BUCKETS 256

struct QuicSession {
    struct Listener *listener;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    const struct Address *backend_address;
    int caller_free_backend_address;
    int backend_fd;
    struct ev_io backend_watcher;
    char *hostname;
    size_t hostname_len;
    struct QuicSession *bucket_next;
    struct QuicSession **bucket_link;
    TAILQ_ENTRY(QuicSession) entries;
};

struct QuicListenerState {
    struct Listener *listener;
    struct ev_loop *loop;
    TAILQ_HEAD(, QuicSession) sessions;
    struct QuicSession **session_buckets;
    size_t session_bucket_count;
    struct QuicListenerStats stats;
};

static struct QuicSession *quic_find_session(struct QuicListenerState *,
        const struct sockaddr_storage *, socklen_t);
static void quic_session_destroy(struct QuicListenerState *, struct QuicSession *);
static int quic_session_init_backend(struct QuicSession *, const struct Address *);
static void backend_cb(struct ev_loop *, struct ev_io *, int);
static size_t quic_hash_sockaddr(const struct sockaddr_storage *, socklen_t);
static void quic_session_bucket_insert(struct QuicListenerState *, struct QuicSession *);
static void quic_session_bucket_remove(struct QuicSession *);

int
quic_listener_attach(struct Listener *listener, struct ev_loop *loop)
{
    if (listener == NULL)
        return -1;

    struct QuicListenerState *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        err("%s: calloc", __func__);
        return -1;
    }

    state->listener = listener;
    state->loop = loop;
    TAILQ_INIT(&state->sessions);
    memset(&state->stats, 0, sizeof(state->stats));

    state->session_bucket_count = QUIC_SESSION_BUCKETS;
    state->session_buckets = calloc(state->session_bucket_count,
            sizeof(*state->session_buckets));
    if (state->session_buckets == NULL) {
        warn("unable to allocate QUIC session buckets, falling back to linear search");
        state->session_bucket_count = 0;
    }

    listener->protocol_data = state;

    return 0;
}

void
quic_listener_detach(struct Listener *listener, struct ev_loop *loop)
{
    (void)loop;

    if (listener == NULL)
        return;

    struct QuicListenerState *state = listener->protocol_data;
    if (state == NULL)
        return;

    struct QuicSession *session;
    while ((session = TAILQ_FIRST(&state->sessions)) != NULL)
        quic_session_destroy(state, session);

    listener->protocol_data = NULL;
    free(state->session_buckets);
    free(state);
}

int
accept_quic_client(struct Listener *listener, struct ev_loop *loop)
{
    if (listener == NULL || listener->protocol_data == NULL)
        return 0;

    struct QuicListenerState *state = listener->protocol_data;
    uint8_t buffer[QUIC_MAX_DATAGRAM];
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t received = recvfrom(listener->watcher.fd, buffer, sizeof(buffer), 0,
            (struct sockaddr *)&client_addr, &client_len);
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            warn("recvfrom failed: %s", strerror(errno));
        return 0;
    }

    state->stats.client_datagrams_received++;

    struct QuicSession *session = quic_find_session(state, &client_addr, client_len);
    if (session != NULL) {
        state->stats.sessions_resumed++;
        ssize_t sent = send(session->backend_fd, buffer, (size_t)received, 0);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("send failed: %s", strerror(errno));
            state->stats.client_send_errors++;
            quic_session_destroy(state, session);
        }
        if (sent >= 0)
            state->stats.client_datagrams_forwarded++;
        return 1;
    }

    char *hostname = NULL;
    size_t hostname_len = 0;
    int parse_result = listener->protocol->parse_packet((const char *)buffer,
            (size_t)received, &hostname);
    if (parse_result < 0) {
        state->stats.parse_failures++;
        char client_buf[ADDRESS_BUFFER_SIZE];
        if (parse_result == -2)
            warn("QUIC request from %s did not include a hostname",
                    display_sockaddr(&client_addr, client_len,
                        client_buf, sizeof(client_buf)));
        else
            warn("Unable to parse QUIC request from %s: parser returned %d",
                    display_sockaddr(&client_addr, client_len,
                        client_buf, sizeof(client_buf)),
                    parse_result);

        if (hostname != NULL) {
            free(hostname);
            hostname = NULL;
        }

        if (listener->fallback_address == NULL)
            return 0;
    } else {
        hostname_len = (size_t)parse_result;
    }

    struct LookupResult lookup = listener_lookup_server_address(listener,
            hostname, hostname_len);
    if (lookup.address == NULL) {
        state->stats.lookup_failures++;
        if (hostname != NULL)
            free(hostname);
        return 0;
    }

    if (lookup.resolved_target != TABLE_LOOKUP_TARGET_HTTP3) {
        const char *log_hostname = (hostname != NULL && hostname_len > 0) ? hostname : "(no hostname)";
        info("No HTTP/3 backend for %s, letting client fall back to TCP", log_hostname);
        state->stats.fallback_invocations++;
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        if (hostname != NULL)
            free(hostname);
        return 0;
    }

    if (!address_is_sockaddr(lookup.address)) {
        warn("QUIC backend must resolve to a socket address");
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        if (hostname != NULL)
            free(hostname);
        return 0;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) {
        err("%s: calloc", __func__);
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        if (hostname != NULL)
            free(hostname);
        return 0;
    }

    session->listener = listener_ref_get(listener);
    memcpy(&session->client_addr, &client_addr, client_len);
    session->client_addr_len = client_len;
    session->backend_address = lookup.address;
    session->caller_free_backend_address = lookup.caller_free_address;
    session->hostname = hostname;
    session->hostname_len = hostname_len;
    session->backend_fd = -1;
    session->bucket_next = NULL;
    session->bucket_link = NULL;

    if (quic_session_init_backend(session, lookup.address) < 0) {
        if (lookup.caller_free_address)
            free((void *)lookup.address);
        if (hostname != NULL)
            free(hostname);
        listener_ref_put(session->listener);
        free(session);
        return 0;
    }

    state->stats.sessions_started++;

    quic_session_bucket_insert(state, session);
    TAILQ_INSERT_HEAD(&state->sessions, session, entries);
    ev_io_start(state->loop, &session->backend_watcher);

    ssize_t sent = send(session->backend_fd, buffer, (size_t)received, 0);
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        warn("send failed: %s", strerror(errno));
        state->stats.client_send_errors++;
        quic_session_destroy(state, session);
        return 0;
    }
    if (sent >= 0)
        state->stats.client_datagrams_forwarded++;

    (void)loop;
    return 1;
}

static struct QuicSession *
quic_find_session(struct QuicListenerState *state,
        const struct sockaddr_storage *addr, socklen_t len)
{
    if (state->session_buckets != NULL && state->session_bucket_count != 0) {
        size_t index = quic_hash_sockaddr(addr, len) &
                (state->session_bucket_count - 1);
        struct QuicSession *session = state->session_buckets[index];

        while (session != NULL) {
            if (session->client_addr_len == len &&
                    memcmp(&session->client_addr, addr, len) == 0)
                return session;
            session = session->bucket_next;
        }

        return NULL;
    }

    struct QuicSession *session;

    TAILQ_FOREACH(session, &state->sessions, entries) {
        if (session->client_addr_len == len &&
                memcmp(&session->client_addr, addr, len) == 0)
            return session;
    }

    return NULL;
}

static int
quic_session_init_backend(struct QuicSession *session, const struct Address *address)
{
    struct QuicListenerState *state = session->listener != NULL ?
            session->listener->protocol_data : NULL;
    int fd = socket(address_sa(address)->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        err("socket failed: %s", strerror(errno));
        if (state != NULL)
            state->stats.backend_init_failures++;
        return -1;
    }

    if (set_cloexec(fd) < 0) {
        err("failed to set close-on-exec on QUIC backend socket: %s",
                strerror(errno));
        close(fd);
        if (state != NULL)
            state->stats.backend_init_failures++;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (connect(fd, address_sa(address), address_sa_len(address)) < 0) {
        err("connect failed: %s", strerror(errno));
        close(fd);
        if (state != NULL)
            state->stats.backend_init_failures++;
        return -1;
    }

    ev_io_init(&session->backend_watcher, backend_cb, fd, EV_READ);
    session->backend_watcher.data = session;
    session->backend_fd = fd;

    return 0;
}

static void
backend_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct QuicSession *session = w->data;
    struct QuicListenerState *state = session->listener->protocol_data;

    if (state == NULL)
        return;

    if (!(revents & EV_READ))
        return;

    uint8_t buffer[QUIC_MAX_DATAGRAM];
    ssize_t received = recv(w->fd, buffer, sizeof(buffer), 0);
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("recv failed: %s", strerror(errno));
            state->stats.backend_receive_errors++;
            quic_session_destroy(state, session);
        }
        return;
    }

    state->stats.backend_datagrams_received++;

    ssize_t sent = sendto(session->listener->watcher.fd, buffer, (size_t)received, 0,
            (struct sockaddr *)&session->client_addr, session->client_addr_len);
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        warn("sendto failed: %s", strerror(errno));
        state->stats.backend_send_errors++;
        quic_session_destroy(state, session);
    }
    if (sent >= 0)
        state->stats.backend_datagrams_forwarded++;

    (void)loop;
}

static void
quic_session_destroy(struct QuicListenerState *state, struct QuicSession *session)
{
    if (session == NULL)
        return;

    ev_io_stop(state->loop, &session->backend_watcher);

    if (session->backend_fd >= 0)
        close(session->backend_fd);

    if (session->caller_free_backend_address)
        free((void *)session->backend_address);

    if (session->hostname != NULL)
        free(session->hostname);

    state->stats.sessions_destroyed++;
    quic_session_bucket_remove(session);
    TAILQ_REMOVE(&state->sessions, session, entries);
    listener_ref_put(session->listener);
    free(session);
}

const struct QuicListenerStats *
quic_listener_get_stats(const struct Listener *listener)
{
    if (listener == NULL || listener->protocol_data == NULL)
        return NULL;

    const struct QuicListenerState *state = listener->protocol_data;
    return &state->stats;
}

void
quic_listener_reset_stats(struct Listener *listener)
{
    if (listener == NULL || listener->protocol_data == NULL)
        return;

    struct QuicListenerState *state = listener->protocol_data;
    memset(&state->stats, 0, sizeof(state->stats));
}

static size_t
quic_hash_sockaddr(const struct sockaddr_storage *addr, socklen_t len)
{
    const unsigned char *data = (const unsigned char *)addr;
    uint64_t hash = 1469598103934665603ULL;

    for (socklen_t i = 0; i < len; ++i) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }

    return (size_t)hash;
}

static void
quic_session_bucket_insert(struct QuicListenerState *state, struct QuicSession *session)
{
    if (state->session_buckets == NULL || state->session_bucket_count == 0)
        return;

    size_t index = quic_hash_sockaddr(&session->client_addr,
            session->client_addr_len) & (state->session_bucket_count - 1);
    struct QuicSession **bucket = &state->session_buckets[index];

    session->bucket_next = *bucket;
    if (session->bucket_next != NULL)
        session->bucket_next->bucket_link = &session->bucket_next;

    *bucket = session;
    session->bucket_link = bucket;
}

static void
quic_session_bucket_remove(struct QuicSession *session)
{
    if (session->bucket_link == NULL)
        return;

    *session->bucket_link = session->bucket_next;
    if (session->bucket_next != NULL)
        session->bucket_next->bucket_link = session->bucket_link;

    session->bucket_link = NULL;
    session->bucket_next = NULL;
}
