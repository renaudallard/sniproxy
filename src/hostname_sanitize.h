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

#include <ctype.h>
#include <stddef.h>

static inline int
sanitize_hostname(char *hostname, size_t *hostname_len, size_t max_len) {
    size_t len;

    if (hostname == NULL || hostname_len == NULL)
        return 0;

    len = *hostname_len;

    while (len > 0 && isspace((unsigned char)hostname[len - 1]))
        len--;

    hostname[len] = '\0';

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

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)hostname[i];

        if (c <= 0x1F || c == 0x7F || c >= 0x80 || isspace(c))
            return 0;

        if (bracketed_ipv6) {
            if (i == 0 || i == len - 1)
                continue;

            if (!(isxdigit(c) || c == ':' || c == '.'))
                return 0;

            hostname[i] = (char)tolower(c);
        } else {
            if (!(isalnum(c) || c == '-' || c == '.' || c == '_'))
                return 0;

            hostname[i] = (char)tolower(c);
        }
    }

    *hostname_len = len;

    return 1;
}

#endif /* HOSTNAME_SANITIZE_H */
