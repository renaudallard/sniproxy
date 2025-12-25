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
#include "xmpp.h"

struct xmpp_test_case {
    const char *stream;
    const char *expected_host;
};

static const struct xmpp_test_case good[] = {
    /* Standard XMPP client stream with XML declaration */
    {
        "<?xml version='1.0'?>"
        "<stream:stream to=\"example.com\" xmlns=\"jabber:client\" "
        "xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">",
        "example.com"
    },
    /* Without XML declaration */
    {
        "<stream:stream to=\"example.com\" xmlns=\"jabber:client\" "
        "xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">",
        "example.com"
    },
    /* Single quotes for attribute value */
    {
        "<stream:stream to='example.com' xmlns='jabber:client'>",
        "example.com"
    },
    /* 'to' attribute not first */
    {
        "<stream:stream xmlns=\"jabber:client\" to=\"example.com\" version=\"1.0\">",
        "example.com"
    },
    /* Whitespace variations */
    {
        "<stream:stream   to=\"example.com\"   xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Newlines in tag */
    {
        "<stream:stream\n  to=\"example.com\"\n  xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Tabs in tag */
    {
        "<stream:stream\tto=\"example.com\"\txmlns=\"jabber:client\">",
        "example.com"
    },
    /* Short stream tag (without namespace prefix) */
    {
        "<stream to=\"example.com\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Subdomain */
    {
        "<stream:stream to=\"chat.example.com\" xmlns=\"jabber:client\">",
        "chat.example.com"
    },
    /* XML declaration with double quotes */
    {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<stream:stream to=\"example.com\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Whitespace before stream tag */
    {
        "  \n\t<?xml version='1.0'?>\n"
        "<stream:stream to=\"example.com\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Case sensitivity - hostname should be lowercased */
    {
        "<stream:stream to=\"EXAMPLE.COM\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Mixed case */
    {
        "<stream:stream to=\"Example.Com\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Trailing dot removed */
    {
        "<stream:stream to=\"example.com.\" xmlns=\"jabber:client\">",
        "example.com"
    },
    /* Server-to-server (different namespace, same parsing) */
    {
        "<stream:stream to=\"example.com\" xmlns=\"jabber:server\">",
        "example.com"
    },
    /* Spaces around = */
    {
        "<stream:stream to = \"example.com\" xmlns=\"jabber:client\">",
        "example.com"
    },
};

/* Cases that should return -1 (incomplete) */
static const char *incomplete[] = {
    "",
    "<",
    "<stream",
    "<stream:",
    "<stream:stream",
    "<stream:stream ",
    "<stream:stream to",
    "<stream:stream to=",
    "<stream:stream to=\"",
    "<stream:stream to=\"example.com",
    "<stream:stream to=\"example.com\"",
    "<?xml version='1.0'?>",
    "<?xml version='1.0'?><stream:stream to=\"example.com\"",
    /* Unclosed XML declaration */
    "<?xml version='1.0'",
};

/* Cases that should return error (< -1, but not -1) */
static const char *bad[] = {
    /* No 'to' attribute */
    "<stream:stream xmlns=\"jabber:client\">",
    /* Empty 'to' attribute */
    "<stream:stream to=\"\" xmlns=\"jabber:client\">",
    /* Invalid hostname characters */
    "<stream:stream to=\"example.com/path\" xmlns=\"jabber:client\">",
    "<stream:stream to=\"example.com@user\" xmlns=\"jabber:client\">",
    /* Not a stream tag */
    "<message to=\"example.com\">",
    /* Unquoted attribute value */
    "<stream:stream to=example.com xmlns=\"jabber:client\">",
    /* Control characters in hostname */
    "<stream:stream to=\"example\x01.com\" xmlns=\"jabber:client\">",
    /* IPv6 without brackets - should fail hostname validation */
    "<stream:stream to=\"2001:db8::1\" xmlns=\"jabber:client\">",
    /* Non-ASCII characters */
    "<stream:stream to=\"ex\x80mple.com\" xmlns=\"jabber:client\">",
    /* Hostname starting with dash */
    "<stream:stream to=\"-example.com\" xmlns=\"jabber:client\">",
    /* Other XML tag before stream */
    "<auth>data</auth><stream:stream to=\"example.com\">",
    /* Space in hostname */
    "<stream:stream to=\"example .com\" xmlns=\"jabber:client\">",
    /* Percent encoding attempt */
    "<stream:stream to=\"example%2ecom\" xmlns=\"jabber:client\">",
    /* Wrong stream namespace element (not stream:stream) */
    "<stream:features>",
    "<stream:x to=\"example.com\">",
    /* Case-sensitive - uppercase should fail */
    "<STREAM:stream to=\"example.com\">",
    "<Stream:Stream to=\"example.com\">",
};

int main(void) {
    unsigned int i;
    int result;
    char *hostname;

    printf("Testing valid XMPP streams...\n");
    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        hostname = NULL;

        result = xmpp_protocol->parse_packet(good[i].stream,
                strlen(good[i].stream), &hostname);

        if (result != (int)strlen(good[i].expected_host)) {
            fprintf(stderr, "FAIL good[%u]: expected len %zu, got %d\n",
                    i, strlen(good[i].expected_host), result);
            fprintf(stderr, "  input: %s\n", good[i].stream);
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

    printf("Testing incomplete XMPP streams...\n");
    for (i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); i++) {
        hostname = NULL;

        result = xmpp_protocol->parse_packet(incomplete[i],
                strlen(incomplete[i]), &hostname);

        if (result != -1) {
            fprintf(stderr, "FAIL incomplete[%u]: expected -1, got %d\n",
                    i, result);
            fprintf(stderr, "  input: %s\n", incomplete[i]);
            assert(0);
        }

        assert(hostname == NULL);
    }
    printf("  %zu incomplete cases passed\n", sizeof(incomplete) / sizeof(incomplete[0]));

    printf("Testing invalid XMPP streams...\n");
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        hostname = NULL;

        result = xmpp_protocol->parse_packet(bad[i],
                strlen(bad[i]), &hostname);

        if (result >= 0 || result == -1) {
            fprintf(stderr, "FAIL bad[%u]: expected error (<-1), got %d\n",
                    i, result);
            fprintf(stderr, "  input: %s\n", bad[i]);
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
    result = xmpp_protocol->parse_packet("<stream:stream to=\"example.com\">",
            32, NULL);
    assert(result == -3);

    /* Test oversized input */
    printf("Testing oversized input...\n");
    char *oversized = malloc(5000);
    assert(oversized != NULL);
    memset(oversized, 'x', 4999);
    oversized[4999] = '\0';
    hostname = NULL;
    result = xmpp_protocol->parse_packet(oversized, 4999, &hostname);
    assert(result < 0);
    assert(hostname == NULL);
    free(oversized);

    /* Test exact boundary: "<stream:stream" is 14 chars, need 15 to check delimiter */
    printf("Testing boundary conditions...\n");
    hostname = NULL;
    result = xmpp_protocol->parse_packet("<stream:stream", 14, &hostname);
    assert(result == -1);  /* incomplete */
    assert(hostname == NULL);

    /* "<stream:stream " is 15 chars - should still be incomplete (no >) */
    hostname = NULL;
    result = xmpp_protocol->parse_packet("<stream:stream ", 15, &hostname);
    assert(result == -1);
    assert(hostname == NULL);

    /* "<stream " is 8 chars */
    hostname = NULL;
    result = xmpp_protocol->parse_packet("<stream ", 8, &hostname);
    assert(result == -1);
    assert(hostname == NULL);

    /* Test <stream:s should be incomplete, not error */
    hostname = NULL;
    result = xmpp_protocol->parse_packet("<stream:s", 9, &hostname);
    assert(result == -1);  /* incomplete - could be <stream:stream */
    assert(hostname == NULL);

    /* Test bracketed IPv6 in to attribute */
    hostname = NULL;
    result = xmpp_protocol->parse_packet(
        "<stream:stream to=\"[2001:db8::1]\" xmlns=\"jabber:client\">",
        57, &hostname);
    assert(result == 13);  /* [2001:db8::1] is 13 chars */
    assert(hostname != NULL);
    assert(strcmp(hostname, "[2001:db8::1]") == 0);
    free(hostname);

    printf("All XMPP tests passed!\n");
    return 0;
}
