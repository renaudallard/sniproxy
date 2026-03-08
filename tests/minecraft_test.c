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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "minecraft.h"

/*
 * Helper to build a Minecraft handshake packet.
 * Returns the total packet size written into buf.
 */
static size_t
build_handshake(unsigned char *buf, size_t buf_size,
        uint32_t protocol_version, const char *address, size_t address_len,
        uint16_t port, uint8_t next_state) {
    unsigned char payload[512];
    size_t pos = 0;

    /* Packet ID = 0x00 */
    payload[pos++] = 0x00;

    /* Protocol version as VarInt */
    uint32_t v = protocol_version;
    do {
        unsigned char byte = v & 0x7F;
        v >>= 7;
        if (v != 0)
            byte |= 0x80;
        payload[pos++] = byte;
    } while (v != 0);

    /* Server address: VarInt length + raw bytes */
    uint32_t alen = (uint32_t)address_len;
    do {
        unsigned char byte = alen & 0x7F;
        alen >>= 7;
        if (alen != 0)
            byte |= 0x80;
        payload[pos++] = byte;
    } while (alen != 0);
    memcpy(payload + pos, address, address_len);
    pos += address_len;

    /* Port (big-endian) */
    payload[pos++] = (unsigned char)(port >> 8);
    payload[pos++] = (unsigned char)(port & 0xFF);

    /* Next state */
    payload[pos++] = next_state;

    /* Now prepend the packet length VarInt */
    size_t out = 0;
    uint32_t plen = (uint32_t)pos;
    do {
        unsigned char byte = plen & 0x7F;
        plen >>= 7;
        if (plen != 0)
            byte |= 0x80;
        assert(out < buf_size);
        buf[out++] = byte;
    } while (plen != 0);

    assert(out + pos <= buf_size);
    memcpy(buf + out, payload, pos);
    return out + pos;
}

struct minecraft_test_case {
    const unsigned char *packet;
    size_t packet_len;
    const char *expected_host;
};

/* Pre-built good packets using build_handshake in main() would be complex,
 * so we use raw byte arrays instead. */

/* example.com, protocol 763 (1.20.1), port 25565, login (next_state=2) */
static const unsigned char pkt_example_com[] = {
    0x12,                                       /* packet length: 18 */
    0x00,                                       /* packet ID: 0x00 */
    0xfb, 0x05,                                 /* protocol version: 763 */
    0x0b,                                       /* address length: 11 */
    'e','x','a','m','p','l','e','.','c','o','m',/* "example.com" */
    0x63, 0xdd,                                 /* port: 25565 */
    0x02,                                       /* next state: login */
};

/* mc.example.com, status ping (next_state=1) */
static const unsigned char pkt_subdomain[] = {
    0x15,
    0x00,
    0xfb, 0x05,
    0x0e,
    'm','c','.','e','x','a','m','p','l','e','.','c','o','m',
    0x63, 0xdd,
    0x01,
};

/* EXAMPLE.COM (uppercase, should be lowercased) */
static const unsigned char pkt_uppercase[] = {
    0x12,
    0x00,
    0xfb, 0x05,
    0x0b,
    'E','X','A','M','P','L','E','.','C','O','M',
    0x63, 0xdd,
    0x02,
};

/* example.com. (trailing dot, should be stripped) */
static const unsigned char pkt_trailing_dot[] = {
    0x13,
    0x00,
    0xfb, 0x05,
    0x0c,
    'e','x','a','m','p','l','e','.','c','o','m','.',
    0x63, 0xdd,
    0x02,
};

/* example.com\0FML\0 (FML marker, should be stripped at NUL) */
static const unsigned char pkt_fml[] = {
    0x17,
    0x00,
    0xfb, 0x05,
    0x10,
    'e','x','a','m','p','l','e','.','c','o','m','\0','F','M','L','\0',
    0x63, 0xdd,
    0x02,
};

/* example.com\0FML2\0 */
static const unsigned char pkt_fml2[] = {
    0x18,
    0x00,
    0xfb, 0x05,
    0x11,
    'e','x','a','m','p','l','e','.','c','o','m','\0','F','M','L','2','\0',
    0x63, 0xdd,
    0x02,
};

/* BungeeCord forwarding: example.com\0127.0.0.1\0uuid */
static const unsigned char pkt_bungee[] = {
    0x21,
    0x00,
    0xfb, 0x05,
    0x1a,
    'e','x','a','m','p','l','e','.','c','o','m',
    '\0','1','2','7','.','0','.','0','.','1',
    '\0','u','u','i','d',
    0x63, 0xdd,
    0x02,
};

/* Short hostname "mc", protocol version 47 (1.8.x) */
static const unsigned char pkt_short[] = {
    0x08,
    0x00,
    0x2f,
    0x02,
    'm','c',
    0x63, 0xdd,
    0x02,
};

/* Port 443 */
static const unsigned char pkt_port443[] = {
    0x12,
    0x00,
    0xfb, 0x05,
    0x0b,
    'e','x','a','m','p','l','e','.','c','o','m',
    0x01, 0xbb,
    0x02,
};

static const struct minecraft_test_case good[] = {
    { pkt_example_com,   sizeof(pkt_example_com),   "example.com" },
    { pkt_subdomain,     sizeof(pkt_subdomain),     "mc.example.com" },
    { pkt_uppercase,     sizeof(pkt_uppercase),     "example.com" },
    { pkt_trailing_dot,  sizeof(pkt_trailing_dot),  "example.com" },
    { pkt_fml,           sizeof(pkt_fml),           "example.com" },
    { pkt_fml2,          sizeof(pkt_fml2),          "example.com" },
    { pkt_bungee,        sizeof(pkt_bungee),        "example.com" },
    { pkt_short,         sizeof(pkt_short),         "mc" },
    { pkt_port443,       sizeof(pkt_port443),       "example.com" },
};

/* Incomplete packets (should return -1) */
static const unsigned char inc_one[] = { 0x10 };
static const unsigned char inc_partial_payload[] = {
    0x10, 0x00, 0xfb, 0x05, 0x0b, 'e', 'x', 'a',
};
/* VarInt with continuation bit but no more data */
static const unsigned char inc_partial_varint[] = { 0x80 };

struct incomplete_case {
    const unsigned char *packet;
    size_t packet_len;
};

static const struct incomplete_case incomplete[] = {
    { inc_one,             0 },  /* empty input */
    { inc_one,             sizeof(inc_one) },
    { inc_partial_payload, sizeof(inc_partial_payload) },
    { inc_partial_varint,  sizeof(inc_partial_varint) },
};

/* Bad packets (should return < -1) */

/* Wrong packet ID (0x01 instead of 0x00) */
static const unsigned char bad_pktid[] = {
    0x12, 0x01, 0xfb, 0x05, 0x0b,
    'e','x','a','m','p','l','e','.','c','o','m',
    0x63, 0xdd, 0x02,
};

/* Address length 0 (no hostname) */
static const unsigned char bad_zero_addr[] = {
    0x07, 0x00, 0xfb, 0x05, 0x00, 0x63, 0xdd, 0x02,
};

/* Address all NUL bytes (hostname empty after stripping) */
static const unsigned char bad_nul_addr[] = {
    0x09, 0x00, 0xfb, 0x05, 0x02, '\0', '\0', 0x63, 0xdd, 0x02,
};

/* Hostname with slash */
static const unsigned char bad_slash[] = {
    0x16, 0x00, 0xfb, 0x05, 0x0f,
    'e','x','a','m','p','l','e','.','c','o','m','/','b','a','d',
    0x63, 0xdd, 0x02,
};

/* Hostname starting with dash */
static const unsigned char bad_dash[] = {
    0x12, 0x00, 0xfb, 0x05, 0x0b,
    '-','e','x','a','m','p','l','e','.','c','m',
    0x63, 0xdd, 0x02,
};

/* Control character in hostname */
static const unsigned char bad_ctrl[] = {
    0x12, 0x00, 0xfb, 0x05, 0x0b,
    'e','x','a','m','p','\x01','e','.','c','o','m',
    0x63, 0xdd, 0x02,
};

/* VarInt overflow: 6 continuation bytes */
static const unsigned char bad_varint[] = {
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
};

/* Declared address length exceeds packet bounds */
static const unsigned char bad_addr_overflow[] = {
    0x08, 0x00, 0xfb, 0x05, 0xff, 0x01,
    'x', 'y',
    0x63, 0xdd, 0x02,
};

/* Packet length 0 */
static const unsigned char bad_zero_len[] = { 0x00 };

struct bad_case {
    const unsigned char *packet;
    size_t packet_len;
};

static const struct bad_case bad[] = {
    { bad_pktid,        sizeof(bad_pktid) },
    { bad_zero_addr,    sizeof(bad_zero_addr) },
    { bad_nul_addr,     sizeof(bad_nul_addr) },
    { bad_slash,        sizeof(bad_slash) },
    { bad_dash,         sizeof(bad_dash) },
    { bad_ctrl,         sizeof(bad_ctrl) },
    { bad_varint,       sizeof(bad_varint) },
    { bad_addr_overflow,sizeof(bad_addr_overflow) },
    { bad_zero_len,     sizeof(bad_zero_len) },
};

int main(void) {
    unsigned int i;
    int result;
    char *hostname;

    printf("Testing valid Minecraft handshakes...\n");
    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        hostname = NULL;

        result = minecraft_protocol->parse_packet(
                (const char *)good[i].packet,
                good[i].packet_len, &hostname);

        if (result != (int)strlen(good[i].expected_host)) {
            fprintf(stderr, "FAIL good[%u]: expected len %zu, got %d\n",
                    i, strlen(good[i].expected_host), result);
            assert(0);
        }

        assert(hostname != NULL);

        if (strcmp(good[i].expected_host, hostname) != 0) {
            fprintf(stderr, "FAIL good[%u]: expected '%s', got '%s'\n",
                    i, good[i].expected_host, hostname);
            assert(0);
        }

        free(hostname);
    }
    printf("  %zu valid cases passed\n", sizeof(good) / sizeof(good[0]));

    printf("Testing incomplete Minecraft handshakes...\n");
    for (i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); i++) {
        hostname = NULL;

        result = minecraft_protocol->parse_packet(
                (const char *)incomplete[i].packet,
                incomplete[i].packet_len, &hostname);

        if (result != -1) {
            fprintf(stderr, "FAIL incomplete[%u]: expected -1, got %d\n",
                    i, result);
            assert(0);
        }

        assert(hostname == NULL);
    }
    printf("  %zu incomplete cases passed\n",
            sizeof(incomplete) / sizeof(incomplete[0]));

    printf("Testing invalid Minecraft handshakes...\n");
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        hostname = NULL;

        result = minecraft_protocol->parse_packet(
                (const char *)bad[i].packet,
                bad[i].packet_len, &hostname);

        if (result >= 0 || result == -1) {
            fprintf(stderr, "FAIL bad[%u]: expected error (<-1), got %d\n",
                    i, result);
            if (hostname != NULL) {
                fprintf(stderr, "  hostname: %s\n", hostname);
                free(hostname);
            }
            assert(0);
        }

        assert(hostname == NULL);
    }
    printf("  %zu invalid cases passed\n", sizeof(bad) / sizeof(bad[0]));

    /* Test NULL hostname pointer */
    printf("Testing NULL hostname pointer...\n");
    result = minecraft_protocol->parse_packet(
            (const char *)pkt_example_com, sizeof(pkt_example_com), NULL);
    assert(result == -3);

    /* Test with build_handshake helper */
    printf("Testing build_handshake helper...\n");
    unsigned char buf[512];
    size_t pkt_len;

    pkt_len = build_handshake(buf, sizeof(buf), 763,
            "test.example.org", 16, 25565, 2);
    hostname = NULL;
    result = minecraft_protocol->parse_packet((const char *)buf,
            pkt_len, &hostname);
    assert(result == 16);
    assert(hostname != NULL);
    assert(strcmp(hostname, "test.example.org") == 0);
    free(hostname);

    /* Build with FML marker */
    pkt_len = build_handshake(buf, sizeof(buf), 763,
            "play.mc.net\0FML\0", 16, 25565, 1);
    hostname = NULL;
    result = minecraft_protocol->parse_packet((const char *)buf,
            pkt_len, &hostname);
    assert(result == 11);
    assert(hostname != NULL);
    assert(strcmp(hostname, "play.mc.net") == 0);
    free(hostname);

    /* Build with long BungeeCord forwarding data (addr field > 255 bytes) */
    printf("Testing long BungeeCord address field (>255 bytes)...\n");
    {
        /*
         * Simulate: mc.example.com\0<ip>\0<uuid>\0<long properties json>
         * The address field is >255 bytes total, but hostname is short.
         */
        char long_addr[400];
        size_t apos = 0;

        memcpy(long_addr + apos, "mc.example.com", 14);
        apos += 14;
        long_addr[apos++] = '\0';

        memcpy(long_addr + apos, "192.168.1.100", 13);
        apos += 13;
        long_addr[apos++] = '\0';

        /* UUID */
        memcpy(long_addr + apos, "069a79f4-44e9-4726-a5be-fca90e38aaf5", 36);
        apos += 36;
        long_addr[apos++] = '\0';

        /* Pad properties to push total past 255 bytes */
        memset(long_addr + apos, 'x', 300 - apos);
        apos = 300;

        pkt_len = build_handshake(buf, sizeof(buf), 763,
                long_addr, apos, 25565, 2);
        hostname = NULL;
        result = minecraft_protocol->parse_packet((const char *)buf,
                pkt_len, &hostname);
        assert(result == 14);
        assert(hostname != NULL);
        assert(strcmp(hostname, "mc.example.com") == 0);
        free(hostname);
    }

    /* Modern Forge marker */
    pkt_len = build_handshake(buf, sizeof(buf), 766,
            "play.mc.net\0FORGE0", 18, 25565, 2);
    hostname = NULL;
    result = minecraft_protocol->parse_packet((const char *)buf,
            pkt_len, &hostname);
    assert(result == 11);
    assert(hostname != NULL);
    assert(strcmp(hostname, "play.mc.net") == 0);
    free(hostname);

    printf("All Minecraft tests passed!\n");
    return 0;
}
