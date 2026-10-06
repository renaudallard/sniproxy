/*
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
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
#include "http2.h"
#include "http.h"

static const unsigned char http2_preface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static const unsigned char http2_single_request[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    "\x00\x00\x0e\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84\x41\x09"
    "localhost";

static const unsigned char http2_unbracketed_ipv6[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    "\x00\x00\x10\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84\x41\x0b"
    "2001:db8::1";

static const unsigned char http_host_with_nul[] =
    "GET / HTTP/1.1\r\n"
    "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
    "Host: example.com\0.evil\r\n"
    "Accept: */*\r\n"
    "\r\n";

/* SETTINGS_HEADER_TABLE_SIZE describes the client's own decoder and may
 * carry any value; it must not fail parsing of the request that follows. */
static const unsigned char http2_large_table_size_setting[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x06\x04\x00\x00\x00\x00\x00"
    "\x00\x01\x00\x10\x00\x00"
    "\x00\x00\x0e\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84\x41\x09"
    "localhost";

/* A NUL in :authority must not hide what follows the port */
static const unsigned char http2_authority_with_nul[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    "\x00\x00\x13\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84\x41\x0e"
    "a.com:443\0evil";

/* Only the first complete header block, the client's first request, is
 * searched for the host: a later block is not decoded, and a first block
 * without a host fails at once instead of waiting for more data. */
static const unsigned char http2_hostless_then_host[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    "\x00\x00\x03\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84"
    "\x00\x00\x0e\x01\x05\x00\x00\x00\x03"
    "\x82\x87\x84\x41\x09"
    "localhost";

static const unsigned char http2_hostless_then_partial[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    "\x00\x00\x03\x01\x05\x00\x00\x00\x01"
    "\x82\x87\x84"
    "\x00\x00\x10\x00\x00\x00\x00\x00\x01";

struct http_request_case {
    const char *request;
    const char *expected_host;
};

static const struct http_request_case good[] = {
    {
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: LOCALHOST\r\n"
        "Accept: */*\r\n"
        "\r\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "HOST:\t     localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "HOST:\t     localhost:8080\r\n"
        "Accept: */*\r\n"
        "\r\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\n"
        "Host: localhost\n"
        "Accept: */*\n"
        "\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: [2001:db8::1]:443\r\n"
        "Accept: */*\r\n"
        "\r\n",
        "[2001:db8::1]"
    },
    /* Trailing whitespace after the port */
    {
        "GET / HTTP/1.1\r\n"
        "Host: localhost:8080 \t\r\n"
        "\r\n",
        "localhost"
    },
    {
        "GET / HTTP/1.1\r\n"
        "Host: [2001:db8::1]:443 \r\n"
        "\r\n",
        "[2001:db8::1]"
    },
};
static const char *bad[] = {
    "GET / HTTP/1.0\r\n"
        "\r\n",
    /* A wildcard table entry would take "*" as its own wildcard */
    "GET / HTTP/1.1\r\n"
        "Host: *\r\n"
        "\r\n",
    "",
    "G",
    "GET ",
    "GET / HTTP/1.0\n"
        "\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Hostname: localhost\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: 2001:db8::1\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: example.com:\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: [2001:db8::1]:\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: example.com/evil\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: example.com@evil\r\n"
        "Accept: */*\r\n"
        "\r\n",
    "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.21.0 (x86_64-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
        "Host: localhost\r\n"
        "Host: duplicate.example\r\n"
        "Accept: */*\r\n"
        "\r\n",
    /* Bare Host: with no value */
    "GET / HTTP/1.1\r\n"
        "Host:\r\n"
        "Accept: */*\r\n"
        "\r\n",
    /* Bare Host: followed by a second Host header */
    "GET / HTTP/1.1\r\n"
        "Host:\r\n"
        "Host: evil.com\r\n"
        "Accept: */*\r\n"
        "\r\n",
};

/* Append an HPACK integer with the given prefix size and first byte bits */
static size_t
hpack_put_int(unsigned char *out, size_t value, unsigned prefix_bits,
        unsigned char first) {
    size_t max = ((size_t)1 << prefix_bits) - 1;
    size_t pos = 0;

    if (value < max) {
        out[pos++] = (unsigned char)(first | value);
        return pos;
    }
    out[pos++] = (unsigned char)(first | max);
    value -= max;
    while (value >= 128) {
        out[pos++] = (unsigned char)((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[pos++] = (unsigned char)value;
    return pos;
}

/*
 * A prior knowledge request for "localhost" whose header block also holds
 * an authorization field of token_len bytes, before or after :authority,
 * in frames of 16384 bytes. With bad_field, a field whose value length
 * does not fit a size_t follows :authority. Returns its length.
 */
static size_t
build_large_http2_request(unsigned char *buf, size_t token_len,
        int authority_first, int bad_field) {
    static unsigned char block[200000];
    size_t block_len = 0, pos = 0, sent = 0;
    unsigned char authority[16], token_header[16];
    size_t authority_len, token_header_len;

    authority_len = hpack_put_int(authority, 1, 4, 0x00);
    authority[authority_len++] = 9;
    memcpy(authority + authority_len, "localhost", 9);
    authority_len += 9;
    token_header_len = hpack_put_int(token_header, 23, 4, 0x00);
    token_header_len += hpack_put_int(token_header + token_header_len,
            token_len, 7, 0x00);

    block[block_len++] = 0x82;      /* :method GET */
    block[block_len++] = 0x86;      /* :scheme http */
    block[block_len++] = 0x84;      /* :path / */
    if (authority_first) {
        memcpy(block + block_len, authority, authority_len);
        block_len += authority_len;
    }
    if (bad_field) {
        /* Literal field "x", its value length an integer too large */
        memcpy(block + block_len, "\x00\x01x\x7f"
                "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", 15);
        block_len += 15;
    }
    memcpy(block + block_len, token_header, token_header_len);
    block_len += token_header_len;
    memset(block + block_len, 'A', token_len);
    block_len += token_len;
    if (!authority_first) {
        memcpy(block + block_len, authority, authority_len);
        block_len += authority_len;
    }

    memcpy(buf, http2_preface, sizeof(http2_preface) - 1);
    pos = sizeof(http2_preface) - 1;
    memcpy(buf + pos, "\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9);
    pos += 9;
    while (sent < block_len) {
        size_t len = block_len - sent < 16384 ? block_len - sent : 16384;
        int last = sent + len == block_len;

        buf[pos++] = 0;
        buf[pos++] = (unsigned char)(len >> 8);
        buf[pos++] = (unsigned char)len;
        buf[pos++] = sent == 0 ? 0x1 : 0x9;     /* HEADERS, CONTINUATION */
        buf[pos++] = last ? 0x4 : 0x0;          /* END_HEADERS */
        memcpy(buf + pos, "\x00\x00\x00\x01", 4);
        pos += 4;
        memcpy(buf + pos, block + sent, len);
        pos += len;
        sent += len;
    }

    return pos;
}

int main(void) {
    unsigned int i;
    int result;
    char *hostname;

    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(good[i].request,
                strlen(good[i].request), &hostname);

        assert(result == (int)strlen(good[i].expected_host));

        assert(NULL != hostname);

        assert(strcmp(good[i].expected_host, hostname) == 0);

        free(hostname);
    }

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_single_request,
            sizeof(http2_single_request) - 1, &hostname);
    assert(result == (int)strlen("localhost"));
    assert(hostname != NULL);
    assert(strcmp("localhost", hostname) == 0);
    free(hostname);

    /* A header block over the decoding limit, as a Kerberos token can
     * make, is routed on the :authority found before the limit */
    {
        static unsigned char large[220000];
        size_t large_len = build_large_http2_request(large, 70000, 1, 0);

        hostname = NULL;
        result = http_protocol->parse_packet((const char *)large,
                large_len, &hostname);
        assert(result == (int)strlen("localhost"));
        assert(hostname != NULL);
        assert(strcmp("localhost", hostname) == 0);
        free(hostname);

        large_len = build_large_http2_request(large, 70000, 0, 0);
        hostname = NULL;
        result = http_protocol->parse_packet((const char *)large,
                large_len, &hostname);
        assert(result == -2);
        assert(hostname == NULL);

        /* A malformed field before the limit is refused whatever the
         * size of the block */
        large_len = build_large_http2_request(large, 70000, 1, 1);
        hostname = NULL;
        result = http_protocol->parse_packet((const char *)large,
                large_len, &hostname);
        assert(result == -4);
        assert(hostname == NULL);

        large_len = build_large_http2_request(large, 10, 1, 1);
        hostname = NULL;
        result = http_protocol->parse_packet((const char *)large,
                large_len, &hostname);
        assert(result == -4);
        assert(hostname == NULL);
    }
    free(hostname);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_unbracketed_ipv6,
            sizeof(http2_unbracketed_ipv6) - 1, &hostname);
    assert(result < 0);
    assert(hostname == NULL);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http_host_with_nul,
            sizeof(http_host_with_nul) - 1, &hostname);
    assert(result < 0);
    assert(hostname == NULL);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_large_table_size_setting,
            sizeof(http2_large_table_size_setting) - 1, &hostname);
    assert(result == (int)strlen("localhost"));
    assert(hostname != NULL);
    assert(strcmp("localhost", hostname) == 0);
    free(hostname);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_authority_with_nul,
            sizeof(http2_authority_with_nul) - 1, &hostname);
    assert(result < 0);
    assert(hostname == NULL);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_hostless_then_host,
            sizeof(http2_hostless_then_host) - 1, &hostname);
    assert(result == -2);
    assert(hostname == NULL);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_hostless_then_partial,
            sizeof(http2_hostless_then_partial) - 1, &hostname);
    assert(result == -2);
    assert(hostname == NULL);

    /* Data without a new line cannot complete an HTTP/1 request, while
     * HTTP/2 frames are always parsed again. */
    static const char partial[] = "GET / HTTP/1.1\r\nX-Pad: aaaa";
    size_t partial_len = sizeof(partial) - 1;
    assert(http_protocol->request_may_complete(partial, partial_len,
            partial_len - 4) == 0);
    assert(http_protocol->request_may_complete(partial, partial_len,
            partial_len) == 0);
    static const char more[] = "GET / HTTP/1.1\r\nX-Pad: aaaa\r\n";
    assert(http_protocol->request_may_complete(more, sizeof(more) - 1,
            partial_len) == 1);
    assert(http_protocol->request_may_complete(
            (const char *)http2_single_request,
            sizeof(http2_single_request) - 1,
            sizeof(http2_single_request) - 2) == 1);

    size_t oversized_payload = HTTP2_MAX_HEADER_BLOCK_SIZE + 1;
    size_t oversized_total = sizeof(http2_preface) - 1 + 9 + oversized_payload;
    unsigned char *oversized = malloc(oversized_total);
    assert(oversized != NULL);

    size_t pos = 0;
    memcpy(oversized + pos, http2_preface, sizeof(http2_preface) - 1);
    pos += sizeof(http2_preface) - 1;

    oversized[pos++] = (unsigned char)((oversized_payload >> 16) & 0xFF);
    oversized[pos++] = (unsigned char)((oversized_payload >> 8) & 0xFF);
    oversized[pos++] = (unsigned char)(oversized_payload & 0xFF);
    oversized[pos++] = 0x01; /* HEADERS */
    oversized[pos++] = 0x04; /* END_HEADERS */
    oversized[pos++] = 0x00;
    oversized[pos++] = 0x00;
    oversized[pos++] = 0x00;
    oversized[pos++] = 0x01; /* Stream ID 1 */
    memset(oversized + pos, 0x00, oversized_payload);
    pos += oversized_payload;

    assert(pos == oversized_total);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)oversized, oversized_total, &hostname);
    assert(result < 0);
    assert(hostname == NULL);
    free(oversized);

    for (i = 0; i < sizeof(bad) / sizeof(const char *); i++) {
        hostname = NULL;

        result = http_protocol->parse_packet(bad[i], strlen(bad[i]), &hostname);

        assert(result < 0);

        assert(hostname == NULL);
    }

    return 0;
}

