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
#include "dtls.h"

/*
 * DTLS 1.2 ClientHello with SNI "localhost" (89 bytes total)
 * Generated with correct length fields.
 */
const unsigned char dtls12_sni_localhost[] = {
    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0xfe, 0xfd, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x12, 0x00,
    0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
    0x74,
};

/*
 * DTLS 1.0 ClientHello with SNI "example.com" and a cookie (95 bytes total)
 */
const unsigned char dtls10_sni_example[] = {
    0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x52, 0x01, 0x00, 0x00,
    0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46, 0xfe, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x00, 0x04, 0xde, 0xad, 0xbe,
    0xef, 0x00, 0x04, 0x00, 0x2f, 0x00, 0xff, 0x01,
    0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
};

/* DTLS record that is not a handshake */
const unsigned char dtls_not_handshake[] = {
    0x17,                   /* ContentType: Application Data */
    0xFE, 0xFD,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x05,
    0x01, 0x02, 0x03, 0x04, 0x05,
};

/* DTLS ClientHello with no extensions (69 bytes total) */
const unsigned char dtls_no_extensions[] = {
    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0xfe, 0xfd, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x2f, 0x00, 0xff, 0x01, 0x00,
};

/* Truncated DTLS record (too short for header) */
const unsigned char dtls_truncated[] = {
    0x16, 0xFE, 0xFD, 0x00, 0x00,
};

/* DTLS with non-zero epoch (rekeyed, not initial handshake) */
const unsigned char dtls_nonzero_epoch[] = {
    0x16,
    0xFE, 0xFD,
    0x00, 0x01,             /* Epoch: 1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x05,
    0x01, 0x02, 0x03, 0x04, 0x05,
};

/* DTLS with fragmented ClientHello (fragment_offset != 0) */
const unsigned char dtls_fragmented[] = {
    0x16,
    0xFE, 0xFD,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18,             /* Length: 24 */
    /* Handshake header */
    0x01,                   /* Type: ClientHello */
    0x00, 0x01, 0x00,       /* Length: 256 (full handshake) */
    0x00, 0x00,             /* Message sequence: 0 */
    0x00, 0x00, 0x80,       /* Fragment offset: 128 (not 0) */
    0x00, 0x00, 0x0C,       /* Fragment length: 12 */
    /* fragment data */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};

struct test_case {
    const char *name;
    const unsigned char *data;
    size_t len;
    int expected_result;
    const char *expected_hostname;
};

static struct test_case tests[] = {
    {
        "DTLS 1.2 ClientHello with SNI localhost",
        dtls12_sni_localhost,
        sizeof(dtls12_sni_localhost),
        9,
        "localhost",
    },
    {
        "DTLS 1.0 ClientHello with cookie and SNI example.com",
        dtls10_sni_example,
        sizeof(dtls10_sni_example),
        11,
        "example.com",
    },
    {
        "DTLS not a handshake",
        dtls_not_handshake,
        sizeof(dtls_not_handshake),
        -5,
        NULL,
    },
    {
        "DTLS ClientHello with no extensions",
        dtls_no_extensions,
        sizeof(dtls_no_extensions),
        -2,
        NULL,
    },
    {
        "DTLS truncated",
        dtls_truncated,
        sizeof(dtls_truncated),
        -1,
        NULL,
    },
    {
        "DTLS non-zero epoch",
        dtls_nonzero_epoch,
        sizeof(dtls_nonzero_epoch),
        -5,
        NULL,
    },
    {
        "DTLS fragmented ClientHello",
        dtls_fragmented,
        sizeof(dtls_fragmented),
        -2,
        NULL,
    },
    {
        "NULL hostname pointer",
        dtls12_sni_localhost,
        sizeof(dtls12_sni_localhost),
        -3,
        NULL,
    },
    {
        "Empty data",
        (const unsigned char *)"",
        0,
        -1,
        NULL,
    },
};

int main(void) {
    int failures = 0;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        struct test_case *t = &tests[i];
        char *hostname = NULL;
        char **hostname_ptr = &hostname;

        /* Special case: test NULL hostname pointer */
        if (t->expected_result == -3)
            hostname_ptr = NULL;

        int result = dtls_protocol->parse_packet(
                (const char *)t->data, t->len, hostname_ptr);

        if (result != t->expected_result) {
            fprintf(stderr, "FAIL: %s: expected %d, got %d\n",
                    t->name, t->expected_result, result);
            failures++;
            free(hostname);
            continue;
        }

        if (t->expected_hostname != NULL) {
            if (hostname == NULL) {
                fprintf(stderr, "FAIL: %s: expected hostname '%s', got NULL\n",
                        t->name, t->expected_hostname);
                failures++;
                continue;
            }
            if (strcmp(hostname, t->expected_hostname) != 0) {
                fprintf(stderr, "FAIL: %s: expected hostname '%s', got '%s'\n",
                        t->name, t->expected_hostname, hostname);
                failures++;
                free(hostname);
                continue;
            }
        } else if (hostname != NULL) {
            fprintf(stderr, "FAIL: %s: expected NULL hostname, got '%s'\n",
                    t->name, hostname);
            failures++;
            free(hostname);
            continue;
        }

        printf("PASS: %s\n", t->name);
        free(hostname);
    }

    if (failures > 0) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }

    printf("\nAll DTLS parser tests passed\n");
    return 0;
}
