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
 * Minimal DTLS ClientHello parser for extracting the Server Name Indication
 * extension.  DTLS is TLS over UDP; the record and handshake headers differ
 * from TLS but the ClientHello body and extensions are identical.
 *
 * Reference: RFC 6347 (DTLS 1.2), RFC 9147 (DTLS 1.3)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "dtls.h"
#include "tls.h"
#include "protocol.h"
#include "logger.h"
#include "hostname_sanitize.h"
#include "sni_parse.h"

/* DTLS record header: ContentType(1) + Version(2) + Epoch(2) + SeqNum(6) + Length(2) */
#define DTLS_RECORD_HEADER_LEN 13
/* DTLS handshake header: Type(1) + Length(3) + MsgSeq(2) + FragOffset(3) + FragLen(3) */
#define DTLS_HANDSHAKE_HEADER_LEN 12
#define DTLS_HANDSHAKE_CONTENT_TYPE 0x16
#define DTLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
/* Version(2) + Random(32) */
#define DTLS_CLIENT_HELLO_VERSION_RANDOM_LEN 34

static size_t dtls_max_extensions = TLS_DEFAULT_MAX_EXTENSIONS;
static size_t dtls_max_extension_length = TLS_DEFAULT_MAX_EXTENSION_LENGTH;

static int parse_dtls_header(const char *, size_t, char **);

const struct Protocol *const dtls_protocol = &(struct Protocol){
    .name = "dtls",
    .default_port = 443,
    .parse_packet = &parse_dtls_header,
    .abort_message = NULL,
    .abort_message_len = 0,
    .sock_type = SOCK_DGRAM,
};


/*
 * Parse a DTLS datagram for the Server Name Indication extension in the
 * ClientHello handshake.
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No SNI extension found
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid DTLS ClientHello
 */
static int
parse_dtls_header(const char *data_char, size_t data_len, char **hostname) {
    const uint8_t *data = (const uint8_t *)data_char;
    size_t len;

    if (hostname == NULL)
        return -3;

    if (data_len < DTLS_RECORD_HEADER_LEN)
        return -1;

    /* Content type must be Handshake */
    if (data[0] != DTLS_HANDSHAKE_CONTENT_TYPE) {
        debug("DTLS: not a handshake record (content_type=0x%02x)", data[0]);
        return -5;
    }

    /* DTLS version field: {0xFE, 0xFF} = DTLS 1.0, {0xFE, 0xFD} = DTLS 1.2
     * DTLS 1.3 uses {0xFE, 0xFD} on the wire for compatibility.
     * The high byte is always 0xFE for DTLS. */
    if (data[1] != 0xFE) {
        debug("DTLS: unexpected version major 0x%02x", data[1]);
        return -5;
    }

    /* Epoch must be 0 for initial handshake */
    uint16_t epoch = ((uint16_t)data[3] << 8) | data[4];
    if (epoch != 0) {
        debug("DTLS: non-zero epoch %" PRIu16, epoch);
        return -5;
    }

    /* Record payload length */
    len = ((size_t)data[11] << 8) | data[12];
    if (DTLS_RECORD_HEADER_LEN + len > data_len)
        return -1;

    const uint8_t *record_payload = data + DTLS_RECORD_HEADER_LEN;
    size_t record_payload_len = len;

    /* Handshake header */
    if (record_payload_len < DTLS_HANDSHAKE_HEADER_LEN)
        return -5;

    if (record_payload[0] != DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        debug("DTLS: not a ClientHello (type=0x%02x)", record_payload[0]);
        return -5;
    }

    /* Handshake body length (3 bytes) */
    size_t hs_length = ((size_t)record_payload[1] << 16) |
                        ((size_t)record_payload[2] << 8) |
                        (size_t)record_payload[3];

    /* Fragment offset (3 bytes) */
    size_t frag_offset = ((size_t)record_payload[6] << 16) |
                          ((size_t)record_payload[7] << 8) |
                          (size_t)record_payload[8];

    /* Fragment length (3 bytes) */
    size_t frag_length = ((size_t)record_payload[9] << 16) |
                          ((size_t)record_payload[10] << 8) |
                          (size_t)record_payload[11];

    /* We only handle unfragmented ClientHellos */
    if (frag_offset != 0) {
        debug("DTLS: fragmented ClientHello (offset=%zu), cannot parse SNI",
              frag_offset);
        return -2;
    }

    if (frag_length != hs_length) {
        debug("DTLS: fragment length %zu != handshake length %zu",
              frag_length, hs_length);
        return -2;
    }

    if (DTLS_HANDSHAKE_HEADER_LEN + frag_length > record_payload_len)
        return -5;

    const uint8_t *body = record_payload + DTLS_HANDSHAKE_HEADER_LEN;
    const uint8_t *body_end = body + frag_length;

    /* ClientHello body: Version(2) + Random(32) */
    if ((size_t)(body_end - body) < DTLS_CLIENT_HELLO_VERSION_RANDOM_LEN)
        return -5;

    body += DTLS_CLIENT_HELLO_VERSION_RANDOM_LEN;

    /* Session ID (1 byte length + variable) */
    if ((size_t)(body_end - body) < 1)
        return -5;
    len = (size_t)body[0];
    body += 1;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* Cookie (1 byte length + variable) - DTLS-specific field */
    if ((size_t)(body_end - body) < 1)
        return -5;
    len = (size_t)body[0];
    body += 1;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* Cipher Suites (2 byte length + variable) */
    if ((size_t)(body_end - body) < 2)
        return -5;
    len = ((size_t)body[0] << 8) | (size_t)body[1];
    body += 2;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* Compression Methods (1 byte length + variable) */
    if ((size_t)(body_end - body) < 1)
        return -5;
    len = (size_t)body[0];
    body += 1;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* No extensions present */
    if (body == body_end)
        return -2;

    /* Extensions (2 byte length + variable) */
    if ((size_t)(body_end - body) < 2)
        return -5;
    len = ((size_t)body[0] << 8) | (size_t)body[1];
    body += 2;

    if ((size_t)(body_end - body) < len)
        return -5;

    return sni_parse_extensions(body, len, hostname,
            dtls_max_extensions, dtls_max_extension_length);
}
