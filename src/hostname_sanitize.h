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

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)hostname[i];

        if (c <= 0x1F || c == 0x7F || c >= 0x80 || isspace((unsigned char)c))
            return 0;

        hostname[i] = (char)tolower(c);
    }

    *hostname_len = len;

    return 1;
}

#endif /* HOSTNAME_SANITIZE_H */
