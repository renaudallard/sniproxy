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

/*
 * Utility helpers for sanitizing hostnames parsed from client requests.
 *
 * Ensures that hostname values are within an expected length and free of
 * control characters so they can be safely logged and matched against
 * routing rules.
 */
#ifndef HOSTNAME_SANITIZE_H
#define HOSTNAME_SANITIZE_H

#include <stddef.h>

static inline int
sanitize_hostname(char *hostname, size_t *hostname_len, size_t max_len) {
    size_t len;

    if (hostname == NULL || hostname_len == NULL)
        return 0;

    len = *hostname_len;

    char *end = hostname + len;
    while (end > hostname) {
        unsigned char tail = (unsigned char)*(end - 1);
        if (!(tail == ' ' || (tail >= '\t' && tail <= '\r')))
            break;
        *(end - 1) = '\0';
        end--;
    }

    len = (size_t)(end - hostname);

    if (len == 0 || len > max_len)
        return 0;

    /* Host headers may legally contain only hostnames, IPv4 literals, a
     * wildcard "*", or bracketed IPv6 literals. Reject anything else so we do
     * not match routing rules using unexpected characters such as '/', '@',
     * or '%'. */

    if (len == 1 && hostname[0] == '*') {
        *hostname_len = len;
        return 1;
    }

    int bracketed_ipv6 = 0;
    if (hostname[0] == '[') {
        if (len <= 2 || hostname[len - 1] != ']')
            return 0;
        bracketed_ipv6 = 1;
    } else if (hostname[len - 1] == ']') {
        /* Trailing bracket without a leading one is invalid. */
        return 0;
    }

    if (bracketed_ipv6) {
        char *p = hostname + 1;
        const char *end = hostname + len - 1;
        unsigned int colon_count = 0;

        for (; p < end; p++) {
            unsigned char c = (unsigned char)*p;

            if (c <= 0x1F || c == 0x7F || c >= 0x80 || c == ' ' ||
                (c >= '\t' && c <= '\r'))
                return 0;

            if (c == ':') {
                colon_count++;
            } else if (c != '.') {
                if ((unsigned)(c - '0') <= 9) {
                    /* leave digits as-is */
                } else if ((unsigned)(c - 'A') <= ('F' - 'A')) {
                    c = (unsigned char)(c | 0x20);
                } else if (!((unsigned)(c - 'a') <= ('f' - 'a')))
                    return 0;
            }

            *p = (char)c;
        }

        if (colon_count < 2)
            return 0;
    } else {
        char *p = hostname;
        const char *end = hostname + len;
        int label_len = 0;
        int saw_label = 0;
        int last_was_dash = 0;

        for (; p < end; p++) {
            unsigned char c = (unsigned char)*p;

            if (c <= 0x1F || c == 0x7F || c >= 0x80 || c == ' ' ||
                (c >= '\t' && c <= '\r'))
                return 0;

            if (c == '.') {
                if (label_len == 0 || last_was_dash)
                    return 0;

                label_len = 0;
                last_was_dash = 0;
                continue;
            }

            if ((unsigned)(c - '0') <= 9) {
                last_was_dash = 0;
            } else {
                if ((unsigned)(c - 'A') <= ('Z' - 'A')) {
                    c = (unsigned char)(c | 0x20);
                    last_was_dash = 0;
                } else if ((unsigned)(c - 'a') <= ('z' - 'a')) {
                    last_was_dash = 0;
                } else if (c == '-' || c == '_') {
                    if (label_len == 0)
                        return 0;
                    last_was_dash = 1;
                } else {
                    return 0;
                }
            }

            saw_label = 1;
            label_len++;
            if (label_len > 63)
                return 0;

            *p = (char)c;
        }

        if (!saw_label)
            return 0;

        if (last_was_dash && hostname[len - 1] != '.')
            return 0;

        while (len > 0 && hostname[len - 1] == '.')
            len--;

        hostname[len] = '\0';
    }

    *hostname_len = len;

    return 1;
}

#endif /* HOSTNAME_SANITIZE_H */
