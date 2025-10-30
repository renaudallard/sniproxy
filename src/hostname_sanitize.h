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
