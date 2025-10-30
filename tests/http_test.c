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

static const unsigned char http2_dynamic_table_overflow[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x06\x04\x00\x00\x00\x00\x00"
    "\x00\x01\x00\x10\x00\x00";

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
};
static const char *bad[] = {
    "GET / HTTP/1.0\r\n"
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
};

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

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_unbracketed_ipv6,
            sizeof(http2_unbracketed_ipv6) - 1, &hostname);
    assert(result < 0);
    assert(hostname == NULL);

    hostname = NULL;
    result = http_protocol->parse_packet((const char *)http2_dynamic_table_overflow,
            sizeof(http2_dynamic_table_overflow) - 1, &hostname);
    assert(result < 0);
    assert(hostname == NULL);

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

