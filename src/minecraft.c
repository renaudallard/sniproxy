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
 * Minecraft Java Edition handshake parser for extracting the server address.
 *
 * Minecraft clients send a handshake packet as the very first data:
 *   [VarInt: packet length] [VarInt: packet ID (0x00)]
 *   [VarInt: protocol version] [String: server address]
 *   [uint16 BE: port] [VarInt: next state]
 *
 * The server address field may contain FML markers or BungeeCord
 * forwarding data after NUL bytes, which are stripped before routing.
 */
#include <stdlib.h>
#include <string.h>
#include "minecraft.h"
#include "protocol.h"
#include "hostname_sanitize.h"

#define SERVER_NAME_LEN 256
#define VARINT_MAX_BYTES 5

static int parse_minecraft_handshake(const char *, size_t, char **);

const struct Protocol *const minecraft_protocol = &(struct Protocol){
    .name = "minecraft",
    .default_port = 25565,
    .parse_packet = &parse_minecraft_handshake,
    .abort_message = NULL,
    .abort_message_len = 0,
};

/*
 * Decode a VarInt from data.
 *
 * Returns the number of bytes consumed, or -1 if incomplete, -2 if malformed
 * (more than VARINT_MAX_BYTES with continuation bits set).
 * The decoded value is stored in *value.
 */
static int
decode_varint(const uint8_t *data, size_t data_len, uint32_t *value) {
    uint32_t result = 0;
    size_t i;

    for (i = 0; i < data_len && i < VARINT_MAX_BYTES; i++) {
        result |= (uint32_t)(data[i] & 0x7F) << (i * 7);

        if ((data[i] & 0x80) == 0) {
            *value = result;
            return (int)(i + 1);
        }
    }

    if (i >= VARINT_MAX_BYTES)
        return -2; /* malformed: too many continuation bytes */

    return -1; /* incomplete */
}

/*
 * Parse a Minecraft Java Edition handshake packet.
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No hostname found
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid packet
 */
static int
parse_minecraft_handshake(const char *data_char, size_t data_len,
        char **hostname) {
    const uint8_t *data = (const uint8_t *)data_char;
    uint32_t packet_len, packet_id, protocol_version, addr_len;
    int n;
    size_t pos = 0;

    if (hostname == NULL)
        return -3;

    if (data_len == 0)
        return -1;

    /* Packet length */
    n = decode_varint(data, data_len, &packet_len);
    if (n < 0)
        return n == -2 ? -5 : -1;
    pos += (size_t)n;

    /* Sanity check: a handshake packet cannot exceed a few hundred bytes */
    if (packet_len == 0 || packet_len > 1024)
        return -5;

    /* Wait for the full packet */
    if (pos + packet_len > data_len)
        return -1;

    /* From here on, all data is within the declared packet length,
     * so any parse failure is malformed (not incomplete). */
    size_t pkt_end = pos + packet_len;

    /* Packet ID (must be 0x00 for handshake) */
    n = decode_varint(data + pos, pkt_end - pos, &packet_id);
    if (n < 0 || packet_id != 0x00)
        return -5;
    pos += (size_t)n;

    /* Protocol version (skip) */
    n = decode_varint(data + pos, pkt_end - pos, &protocol_version);
    if (n < 0)
        return -5;
    pos += (size_t)n;

    /* Server address: VarInt length + UTF-8 bytes */
    n = decode_varint(data + pos, pkt_end - pos, &addr_len);
    if (n < 0)
        return -5;
    pos += (size_t)n;

    if (addr_len == 0)
        return -2;

    if (pos + addr_len > pkt_end)
        return -5;

    /* Truncate at first NUL to strip FML/BungeeCord metadata */
    size_t hostname_len = addr_len;
    const uint8_t *addr = data + pos;
    for (size_t i = 0; i < addr_len; i++) {
        if (addr[i] == '\0') {
            hostname_len = i;
            break;
        }
    }

    if (hostname_len == 0 || hostname_len > SERVER_NAME_LEN - 1)
        return hostname_len == 0 ? -2 : -5;

    char *result = malloc(hostname_len + 1);
    if (result == NULL)
        return -4;

    memcpy(result, addr, hostname_len);
    result[hostname_len] = '\0';

    if (!sanitize_hostname(result, &hostname_len, SERVER_NAME_LEN - 1)) {
        free(result);
        return -5;
    }

    *hostname = result;
    return (int)hostname_len;
}
