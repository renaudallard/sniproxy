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

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <ev.h>

#include "address.h"
#include "backend.h"
#include "listener.h"
#include "quic.h"
#include "quic_listener.h"
#include "table.h"
#include "tls.h"

static size_t
encode_varint(uint8_t *out, size_t value)
{
    if (value < (1ULL << 6)) {
        out[0] = (uint8_t)value;
        return 1;
    }

    if (value < (1ULL << 14)) {
        out[0] = 0x40 | (uint8_t)((value >> 8) & 0x3f);
        out[1] = (uint8_t)(value & 0xff);
        return 2;
    }

    if (value < (1ULL << 30)) {
        out[0] = 0x80 | (uint8_t)((value >> 24) & 0x3f);
        out[1] = (uint8_t)((value >> 16) & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        out[3] = (uint8_t)(value & 0xff);
        return 4;
    }

    out[0] = 0xc0 | (uint8_t)((value >> 56) & 0x3f);
    out[1] = (uint8_t)((value >> 48) & 0xff);
    out[2] = (uint8_t)((value >> 40) & 0xff);
    out[3] = (uint8_t)((value >> 32) & 0xff);
    out[4] = (uint8_t)((value >> 24) & 0xff);
    out[5] = (uint8_t)((value >> 16) & 0xff);
    out[6] = (uint8_t)((value >> 8) & 0xff);
    out[7] = (uint8_t)(value & 0xff);
    return 8;
}

static size_t
build_tls_client_hello(uint8_t *out, size_t out_len, const char *hostname)
{
    size_t host_len = hostname != NULL ? strlen(hostname) : 0;
    size_t extension_payload_len = hostname != NULL ? (5 + host_len) : 0;
    size_t extension_total_len = hostname != NULL ? (4 + extension_payload_len) : 0;
    size_t handshake_body_len = 43 + extension_total_len;
    size_t handshake_total_len = 4 + handshake_body_len;
    size_t record_len = handshake_total_len;

    if (out_len < 5 + handshake_total_len)
        return 0;

    size_t pos = 0;
    out[pos++] = 0x16;
    out[pos++] = 0x03;
    out[pos++] = 0x01;
    out[pos++] = (uint8_t)((record_len >> 8) & 0xff);
    out[pos++] = (uint8_t)(record_len & 0xff);
    out[pos++] = 0x01;
    out[pos++] = (uint8_t)((handshake_body_len >> 16) & 0xff);
    out[pos++] = (uint8_t)((handshake_body_len >> 8) & 0xff);
    out[pos++] = (uint8_t)(handshake_body_len & 0xff);
    out[pos++] = 0x03;
    out[pos++] = 0x03;
    for (int i = 0; i < 32; i++)
        out[pos++] = (uint8_t)(i + 1);
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x02;
    out[pos++] = 0x00;
    out[pos++] = 0x2f;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = (uint8_t)((extension_total_len >> 8) & 0xff);
    out[pos++] = (uint8_t)(extension_total_len & 0xff);

    if (hostname != NULL) {
        size_t server_name_list_len = 3 + host_len;
        out[pos++] = 0x00;
        out[pos++] = 0x00;
        out[pos++] = (uint8_t)((extension_payload_len >> 8) & 0xff);
        out[pos++] = (uint8_t)(extension_payload_len & 0xff);
        out[pos++] = (uint8_t)((server_name_list_len >> 8) & 0xff);
        out[pos++] = (uint8_t)(server_name_list_len & 0xff);
        out[pos++] = 0x00;
        out[pos++] = (uint8_t)((host_len >> 8) & 0xff);
        out[pos++] = (uint8_t)(host_len & 0xff);
        memcpy(out + pos, hostname, host_len);
        pos += host_len;
    }

    return pos;
}

static size_t
build_quic_initial(uint8_t *out, size_t out_len, const char *hostname)
{
    uint8_t tls_payload[512];
    size_t tls_len = build_tls_client_hello(tls_payload, sizeof(tls_payload), hostname);
    if (tls_len == 0)
        return 0;

    uint8_t payload[1024];
    size_t payload_pos = 0;
    payload[payload_pos++] = 0x06;
    payload_pos += encode_varint(payload + payload_pos, 0);
    payload_pos += encode_varint(payload + payload_pos, tls_len);
    memcpy(payload + payload_pos, tls_payload, tls_len);
    payload_pos += tls_len;

    uint8_t length_encoded[8];
    size_t pn_length = 1;
    size_t length_field = pn_length + payload_pos;
    size_t length_len = encode_varint(length_encoded, length_field);

    if (out_len < 1 + 4 + 1 + 4 + 1 + length_len + pn_length + payload_pos)
        return 0;

    size_t pos = 0;
    out[pos++] = 0xc0;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x04;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x02;
    out[pos++] = 0x03;
    out[pos++] = 0x04;
    out[pos++] = 0x04;
    out[pos++] = 0x05;
    out[pos++] = 0x06;
    out[pos++] = 0x07;
    out[pos++] = 0x08;
    out[pos++] = 0x00;
    memcpy(out + pos, length_encoded, length_len);
    pos += length_len;
    out[pos++] = 0x01;
    memcpy(out + pos, payload, payload_pos);
    pos += payload_pos;

    return pos;
}

static int
create_udp_socket(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    socklen_t len = sizeof(addr);
    rc = getsockname(fd, (struct sockaddr *)&addr, &len);
    assert(rc == 0);

    if (port != NULL)
        *port = ntohs(addr.sin_port);

    return fd;
}

static void
set_socket_timeout(int fd)
{
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    assert(rc == 0);
}

static struct Listener *
prepare_listener(struct ev_loop *loop, int listener_fd, const char *address_str, struct Table *table)
{
    struct Listener *listener = new_listener();
    assert(listener != NULL);
    listener->reference_count = 1;
    listener->protocol = quic_protocol;
    listener->accept_cb = accept_quic_client;
    listener->watcher.fd = listener_fd;
    listener->watcher.data = listener;
    listener->address = new_address(address_str);
    assert(listener->address != NULL);

    if (table != NULL)
        listener->table = table_ref_get(table);

    int rc = quic_listener_attach(listener, loop);
    assert(rc == 0);

    quic_listener_reset_stats(listener);
    return listener;
}

static void
cleanup_listener(struct Listener *listener, struct ev_loop *loop)
{
    if (listener == NULL)
        return;

    quic_listener_detach(listener, loop);
    table_ref_put(listener->table);
    listener->table = NULL;
    listener_ref_put(listener);
}

static void
configure_backend(struct Table *table, const char *pattern, const char *http_addr, const char *udp_addr)
{
    struct Backend *backend = new_backend();
    assert(backend != NULL);
    int rc = accept_backend_arg(backend, pattern);
    assert(rc == 1);
    rc = accept_backend_arg(backend, http_addr);
    assert(rc == 1);
    if (udp_addr != NULL) {
        rc = accept_backend_arg(backend, udp_addr);
        assert(rc == 1);
    }
    add_backend(&table->backends, backend);
    rc = init_backend(backend);
    assert(rc == 1);
}

static void
test_quic_connection_success(void)
{
    struct ev_loop *loop = ev_loop_new(0);
    assert(loop != NULL);

    uint16_t listener_port;
    int listener_fd = create_udp_socket(&listener_port);
    set_socket_timeout(listener_fd);

    uint16_t backend_port;
    int backend_fd = create_udp_socket(&backend_port);
    set_socket_timeout(backend_fd);

    int client_fd = create_udp_socket(NULL);
    set_socket_timeout(client_fd);

    char listener_addr_buf[64];
    snprintf(listener_addr_buf, sizeof(listener_addr_buf), "127.0.0.1:%u", listener_port);

    char backend_addr_buf[64];
    snprintf(backend_addr_buf, sizeof(backend_addr_buf), "127.0.0.1:%u", backend_port);

    char backend_udp_arg[64];
    snprintf(backend_udp_arg, sizeof(backend_udp_arg), "udp=127.0.0.1:%u", backend_port);

    struct Table *table = new_table();
    assert(table != NULL);
    configure_backend(table, "^test\\.example$", backend_addr_buf, backend_udp_arg);

    struct Listener *listener = prepare_listener(loop, listener_fd, listener_addr_buf, table);

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(listener_port);

    uint8_t packet[1024];
    size_t packet_len = build_quic_initial(packet, sizeof(packet), "test.example");
    assert(packet_len > 0);

    ssize_t sent = sendto(client_fd, packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target));
    assert(sent == (ssize_t)packet_len);

    int accept_result = accept_quic_client(listener, loop);
    assert(accept_result == 1);

    const struct QuicListenerStats *stats = quic_listener_get_stats(listener);
    assert(stats != NULL);
    assert(stats->client_datagrams_received == 1);
    assert(stats->sessions_started == 1);
    assert(stats->client_datagrams_forwarded == 1);
    assert(stats->sessions_resumed == 0);
    assert(stats->fallback_invocations == 0);

    uint8_t backend_buffer[2048];
    struct sockaddr_storage proxy_addr;
    socklen_t proxy_len = sizeof(proxy_addr);
    ssize_t backend_received = recvfrom(backend_fd, backend_buffer, sizeof(backend_buffer), 0,
            (struct sockaddr *)&proxy_addr, &proxy_len);
    assert(backend_received == (ssize_t)packet_len);

    const uint8_t response[] = {0xde, 0xad, 0xbe, 0xef};
    ssize_t backend_sent = sendto(backend_fd, response, sizeof(response), 0,
            (struct sockaddr *)&proxy_addr, proxy_len);
    assert(backend_sent == (ssize_t)sizeof(response));

    for (int i = 0; i < 5; i++)
        ev_run(loop, EVRUN_NOWAIT);

    uint8_t client_buffer[sizeof(response)];
    struct sockaddr_storage from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t client_received = recvfrom(client_fd, client_buffer, sizeof(client_buffer), 0,
            (struct sockaddr *)&from_addr, &from_len);
    assert(client_received == (ssize_t)sizeof(response));
    assert(memcmp(client_buffer, response, sizeof(response)) == 0);

    stats = quic_listener_get_stats(listener);
    assert(stats->backend_datagrams_received == 1);
    assert(stats->backend_datagrams_forwarded == 1);
    assert(stats->client_send_errors == 0);
    assert(stats->backend_send_errors == 0);
    assert(stats->backend_receive_errors == 0);

    cleanup_listener(listener, loop);
    ev_loop_destroy(loop);

    close(client_fd);
    close(listener_fd);
    close(backend_fd);
}

static void
test_quic_http_fallback(void)
{
    struct ev_loop *loop = ev_loop_new(0);
    assert(loop != NULL);

    uint16_t listener_port;
    int listener_fd = create_udp_socket(&listener_port);
    set_socket_timeout(listener_fd);

    char listener_addr_buf[64];
    snprintf(listener_addr_buf, sizeof(listener_addr_buf), "127.0.0.1:%u", listener_port);

    struct Table *table = new_table();
    assert(table != NULL);
    configure_backend(table, "^fallback\\.example$", "127.0.0.1:8443", NULL);

    struct Listener *listener = prepare_listener(loop, listener_fd, listener_addr_buf, table);

    int client_fd = create_udp_socket(NULL);
    set_socket_timeout(client_fd);

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(listener_port);

    uint8_t packet[1024];
    size_t packet_len = build_quic_initial(packet, sizeof(packet), "fallback.example");
    assert(packet_len > 0);

    ssize_t sent = sendto(client_fd, packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target));
    assert(sent == (ssize_t)packet_len);

    int accept_result = accept_quic_client(listener, loop);
    assert(accept_result == 0);

    const struct QuicListenerStats *stats = quic_listener_get_stats(listener);
    assert(stats != NULL);
    assert(stats->client_datagrams_received == 1);
    assert(stats->fallback_invocations == 1);
    assert(stats->sessions_started == 0);
    assert(stats->client_datagrams_forwarded == 0);
    assert(stats->parse_failures == 0);

    cleanup_listener(listener, loop);
    ev_loop_destroy(loop);

    close(listener_fd);
    close(client_fd);
}

static void
test_quic_parse_failure(void)
{
    struct ev_loop *loop = ev_loop_new(0);
    assert(loop != NULL);

    uint16_t listener_port;
    int listener_fd = create_udp_socket(&listener_port);
    set_socket_timeout(listener_fd);

    char listener_addr_buf[64];
    snprintf(listener_addr_buf, sizeof(listener_addr_buf), "127.0.0.1:%u", listener_port);

    struct Listener *listener = prepare_listener(loop, listener_fd, listener_addr_buf, NULL);

    int client_fd = create_udp_socket(NULL);
    set_socket_timeout(client_fd);

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(listener_port);

    uint8_t packet[1024];
    size_t packet_len = build_quic_initial(packet, sizeof(packet), NULL);
    assert(packet_len > 0);

    ssize_t sent = sendto(client_fd, packet, packet_len, 0, (struct sockaddr *)&target, sizeof(target));
    assert(sent == (ssize_t)packet_len);

    int accept_result = accept_quic_client(listener, loop);
    assert(accept_result == 0);

    const struct QuicListenerStats *stats = quic_listener_get_stats(listener);
    assert(stats != NULL);
    assert(stats->client_datagrams_received == 1);
    assert(stats->parse_failures == 1);
    assert(stats->sessions_started == 0);
    assert(stats->fallback_invocations == 0);

    cleanup_listener(listener, loop);
    ev_loop_destroy(loop);

    close(listener_fd);
    close(client_fd);
}

int
main(void)
{
    quic_set_runtime_enabled(1);
    test_quic_connection_success();
    test_quic_http_fallback();
    test_quic_parse_failure();
    return EXIT_SUCCESS;
}
