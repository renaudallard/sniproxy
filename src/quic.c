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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef HAVE_QUICHE
#include <netinet/in.h>
#include <stdlib.h>
#include <quiche.h>
#endif

#include "logger.h"
#include "quic.h"
#include "tls.h"
#include "hostname_sanitize.h"

#ifdef HAVE_QUICHE
static int runtime_http3_enabled;
#endif

int
quic_runtime_enabled(void)
{
#ifdef HAVE_QUICHE
    return runtime_http3_enabled;
#else
    return 0;
#endif
}

void
quic_set_runtime_enabled(int enabled)
{
#ifdef HAVE_QUICHE
    runtime_http3_enabled = enabled ? 1 : 0;
#else
    (void)enabled;
#endif
}

static int parse_quic_initial(const uint8_t *, size_t, char **);
static int parse_quic_initial_manual(const uint8_t *, size_t, char **);
static int quic_read_varint(const uint8_t *, size_t, size_t *, size_t *);

#ifdef HAVE_QUICHE
#define QUIC_SERVER_NAME_MAX_LEN 255
static int quic_parse_with_quiche(const uint8_t *, size_t, char **);
static quiche_config *quic_quiche_config;
#endif

static const char quic_abort[] = "";

const struct Protocol *const quic_protocol = &(struct Protocol){
    .name = "quic",
    .default_port = 443,
    .parse_packet = (int (*const)(const char *, size_t, char **))&parse_quic_initial,
    .abort_message = quic_abort,
    .abort_message_len = sizeof(quic_abort) - 1
};

static int
parse_quic_initial(const uint8_t *data, size_t len, char **hostname)
{
#ifdef HAVE_QUICHE
    int quiche_result = quic_parse_with_quiche(data, len, hostname);
    if (quiche_result >= 0 || quiche_result == -2 || quiche_result == -5)
        return quiche_result;
#endif

    return parse_quic_initial_manual(data, len, hostname);
}

static int
parse_quic_initial_manual(const uint8_t *data, size_t len, char **hostname)
{
    if (hostname == NULL)
        return -3;

    if (len < 1)
        return -1;

    uint8_t first = data[0];
    if ((first & 0x80) == 0)
        return -5;

    uint8_t packet_type = (first >> 4) & 0x03;
    if (packet_type != 0)
        return -5;

    size_t pos = 1;
    if (len - pos < 4)
        return -1;
    pos += 4; /* Version */

    if (pos >= len)
        return -1;
    uint8_t dcid_len = data[pos++];
    if (len - pos < dcid_len)
        return -1;
    pos += dcid_len;

    if (pos >= len)
        return -1;
    uint8_t scid_len = data[pos++];
    if (len - pos < scid_len)
        return -1;
    pos += scid_len;

    size_t token_len;
    size_t consumed;
    if (quic_read_varint(data + pos, len - pos, &token_len, &consumed) < 0)
        return -1;
    pos += consumed;
    if (len - pos < token_len)
        return -1;
    pos += token_len;

    size_t length_field;
    if (quic_read_varint(data + pos, len - pos, &length_field, &consumed) < 0)
        return -1;
    pos += consumed;

    uint8_t pn_length = (first & 0x03) + 1;
    if (length_field < pn_length)
        return -5;

    if (len - pos < pn_length)
        return -1;
    pos += pn_length;

    if (length_field > len - (pos - pn_length))
        return -1;

    size_t payload_len = length_field - pn_length;
    size_t payload_end = pos + payload_len;
    if (payload_end > len)
        return -1;

    while (pos < payload_end) {
        uint8_t frame_type = data[pos];
        if (frame_type == 0x00 || frame_type == 0x01) {
            pos++;
            continue;
        } else if (frame_type == 0x06) {
            pos++;
            size_t offset;
            if (quic_read_varint(data + pos, payload_end - pos, &offset, &consumed) < 0)
                return -1;
            pos += consumed;
            size_t crypto_len;
            if (quic_read_varint(data + pos, payload_end - pos, &crypto_len, &consumed) < 0)
                return -1;
            pos += consumed;
            if (payload_end - pos < crypto_len)
                return -1;
            if (offset == 0) {
                return tls_protocol->parse_packet((const char *)(data + pos),
                        crypto_len, hostname);
            }
            pos += crypto_len;
        } else if (frame_type == 0x02 || frame_type == 0x03) {
            pos++;
            size_t largest, ack_delay, ack_range_count, first_range;
            if (quic_read_varint(data + pos, payload_end - pos, &largest, &consumed) < 0)
                return -1;
            pos += consumed;
            if (quic_read_varint(data + pos, payload_end - pos, &ack_delay, &consumed) < 0)
                return -1;
            pos += consumed;
            if (quic_read_varint(data + pos, payload_end - pos, &ack_range_count, &consumed) < 0)
                return -1;
            pos += consumed;
            if (quic_read_varint(data + pos, payload_end - pos, &first_range, &consumed) < 0)
                return -1;
            pos += consumed;
            for (size_t i = 0; i < ack_range_count; i++) {
                size_t gap, range;
                if (quic_read_varint(data + pos, payload_end - pos, &gap, &consumed) < 0)
                    return -1;
                pos += consumed;
                if (quic_read_varint(data + pos, payload_end - pos, &range, &consumed) < 0)
                    return -1;
                pos += consumed;
            }
        } else {
            warn("Unsupported QUIC frame type 0x%02x", frame_type);
            return -5;
        }
    }

    return -2;
}

#ifdef HAVE_QUICHE
static int
quic_parse_with_quiche(const uint8_t *data, size_t len, char **hostname)
{
    if (hostname == NULL)
        return -3;

    *hostname = NULL;

    if (len < QUICHE_MIN_CLIENT_INITIAL_LEN)
        return -1;

    if (quic_quiche_config == NULL) {
        quic_quiche_config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (quic_quiche_config == NULL)
            return -1;

        quiche_config_set_max_idle_timeout(quic_quiche_config, 60000);
        quiche_config_set_initial_max_data(quic_quiche_config, 1 << 20);
        quiche_config_set_initial_max_stream_data_bidi_local(quic_quiche_config, 1 << 18);
        quiche_config_set_initial_max_stream_data_bidi_remote(quic_quiche_config, 1 << 18);
        quiche_config_set_initial_max_streams_bidi(quic_quiche_config, 128);

        if (quiche_config_set_application_protos(quic_quiche_config,
                    (const uint8_t *)QUICHE_H3_APPLICATION_PROTOCOL,
                    sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1) != 0) {
            quiche_config_free(quic_quiche_config);
            quic_quiche_config = NULL;
            return -1;
        }
    }

    uint32_t version = 0;
    uint8_t packet_type = 0;
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    size_t scid_len = sizeof(scid);
    uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
    size_t dcid_len = sizeof(dcid);
    uint8_t token[256];
    size_t token_len = sizeof(token);

    if (quiche_header_info(data, len, QUICHE_MAX_CONN_ID_LEN, &version,
                &packet_type, scid, &scid_len, dcid, &dcid_len,
                token, &token_len) < 0)
        return -5;

    if (!quiche_version_is_supported(version))
        return -5;

    if ((packet_type & 0x03) != 0)
        return -5;

    struct sockaddr_in dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    dummy_addr.sin_family = AF_INET;

    quiche_conn *conn = quiche_accept(dcid, dcid_len, scid, scid_len,
            (struct sockaddr *)&dummy_addr, sizeof(dummy_addr),
            (struct sockaddr *)&dummy_addr, sizeof(dummy_addr),
            quic_quiche_config);
    if (conn == NULL)
        return -1;

    quiche_recv_info info = {
        .from = (struct sockaddr *)&dummy_addr,
        .from_len = sizeof(dummy_addr),
        .to = (struct sockaddr *)&dummy_addr,
        .to_len = sizeof(dummy_addr),
    };

    ssize_t recv_rc = quiche_conn_recv(conn, (uint8_t *)data, len, &info);
    if (recv_rc < 0 && recv_rc != QUICHE_ERR_DONE) {
        quiche_conn_free(conn);
        return -5;
    }

    const uint8_t *server_name = NULL;
    size_t server_name_len = 0;
    quiche_conn_server_name(conn, &server_name, &server_name_len);

    int result = -2;
    if (server_name != NULL && server_name_len > 0) {
        if (server_name_len > QUIC_SERVER_NAME_MAX_LEN) {
            quiche_conn_free(conn);
            return -5;
        }

        char *copy = malloc(server_name_len + 1);
        if (copy == NULL) {
            quiche_conn_free(conn);
            return -1;
        }

        memcpy(copy, server_name, server_name_len);
        copy[server_name_len] = '\0';

        size_t sanitized_len = server_name_len;
        if (!sanitize_hostname(copy, &sanitized_len, QUIC_SERVER_NAME_MAX_LEN)) {
            free(copy);
            quiche_conn_free(conn);
            return -5;
        }

        copy[sanitized_len] = '\0';
        *hostname = copy;
        result = (int)sanitized_len;
    }

    quiche_conn_free(conn);
    return result;
}
#endif

static int
quic_read_varint(const uint8_t *buf, size_t len, size_t *value, size_t *consumed)
{
    if (len == 0 || value == NULL || consumed == NULL)
        return -1;

    uint8_t prefix = buf[0];
    size_t length = (size_t)1 << (prefix >> 6);
    if (length == 0 || length > len)
        return -1;

    size_t val = prefix & 0x3f;
    for (size_t i = 1; i < length; i++) {
        val = (val << 8) | buf[i];
    }

    *value = val;
    *consumed = length;
    return 0;
}
