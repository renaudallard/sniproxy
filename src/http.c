/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdlib.h> /* malloc() */
#include <string.h> /* memcpy() */
#include <strings.h> /* strncasecmp() */
#include <ctype.h> /* isblank(), isdigit() */
#include "http.h"
#include "protocol.h"
#include "hostname_sanitize.h"
#include "http2.h"

#define SERVER_NAME_LEN 256


static int parse_http_header(const char *, size_t, char **);
static int get_header(const char *, const char *, size_t, char **);
static size_t next_header(const char **, size_t *);


static const char http_503[] =
    "HTTP/1.1 503 Service Temporarily Unavailable\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n\r\n"
    "Backend not available";

const struct Protocol *const http_protocol = &(struct Protocol){
    .name = "http",
    .default_port = 80,
    .parse_packet = &parse_http_header,
    .abort_message = http_503,
    .abort_message_len = sizeof(http_503) - 1,
};

/*
 * Parses a HTTP request for the Host: header
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid HTTP request
 *
 */
static int
parse_http_header(const char* data, size_t data_len, char **hostname) {
    int result;

    if (hostname == NULL)
        return -3;

    static const char http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t preface_len = sizeof(http2_preface) - 1;

    if (data_len > 0) {
        size_t cmp_len = data_len < preface_len ? data_len : preface_len;
        if (cmp_len > 0 && memcmp(data, http2_preface, cmp_len) == 0) {
            int h2_result = parse_http2_header((const unsigned char *)data, data_len, hostname);
            if (h2_result != -4)
                return h2_result;
        }
    }

    result = get_header("Host:", data, data_len, hostname);
    if (result < 0)
        return result;

    char *buffer = *hostname;
    size_t hostname_len = (size_t)result;
    size_t first_colon = hostname_len;
    size_t last_colon = hostname_len;

    for (size_t i = 0; i < hostname_len; i++) {
        if (buffer[i] == ':') {
            if (first_colon == hostname_len)
                first_colon = i;
            last_colon = i;
        }
    }

    if (last_colon != hostname_len) {
        int digits_only = 1;
        size_t port_len = hostname_len - (last_colon + 1);

        if (port_len == 0)
            digits_only = 0;

        for (size_t i = last_colon + 1; i < hostname_len; i++) {
            if (!isdigit((unsigned char)buffer[i])) {
                digits_only = 0;
                break;
            }
        }

        if (digits_only) {
            if (last_colon > 0 && buffer[last_colon - 1] == ':') {
                digits_only = 0;
            } else if (buffer[0] != '[' && first_colon != last_colon) {
                digits_only = 0;
            }
        }

        if (digits_only) {
            hostname_len = last_colon;
            buffer[hostname_len] = '\0';
        }
    }

    if (!sanitize_hostname(*hostname, &hostname_len, SERVER_NAME_LEN - 1)) {
        free(*hostname);
        *hostname = NULL;
        return -5;
    }

    if (hostname_len > 0 && (*hostname)[0] != '[' && strchr(*hostname, ':') != NULL) {
        free(*hostname);
        *hostname = NULL;
        return -5;
    }

    return (int)hostname_len;
}

static int
get_header(const char *header, const char *data, size_t data_len, char **value) {
    size_t len;
    size_t header_len = strlen(header);
    char *found_value = NULL;
    size_t found_len = 0;
    int found = 0;

    /* loop through headers stopping at first blank line */
    while ((len = next_header(&data, &data_len)) != 0) {
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            size_t value_start = header_len;

            /* Eat leading whitespace */
            while (value_start < len && isblank((unsigned char)data[value_start]))
                value_start++;

            size_t value_len = len - value_start;

            if (value_len == 0 || value_len >= SERVER_NAME_LEN) {
                free(found_value);
                return -5;
            }

            if (found) {
                /* Multiple host headers are not permitted */
                free(found_value);
                return -5;
            }

            found_value = malloc(value_len + 1);
            if (found_value == NULL)
                return -4;

            memcpy(found_value, data + value_start, value_len);
            found_value[value_len] = '\0';
            found_len = value_len;
            found = 1;
        }
    }

    /* If there is no data left after reading all the headers then we do not
     * have a complete HTTP request, there must be a blank line */
    if (data_len == 0) {
        free(found_value);
        return -1;
    }

    if (!found)
        return -2;

    *value = found_value;
    return (int)found_len;
}

static size_t
next_header(const char **data, size_t *len) {
    if (*len == 0)
        return 0;

    const char *cursor = *data;
    const char *line_end = memchr(cursor, '\n', *len);

    if (line_end == NULL) {
        /* Incomplete line, consume the remaining bytes */
        *data = cursor + *len;
        *len = 0;
        return 0;
    }

    /* Skip the current line (request line or previous header) */
    size_t consumed = (size_t)(line_end - cursor) + 1;
    cursor = line_end + 1;
    *len -= consumed;
    *data = cursor;

    if (*len == 0)
        return 0;

    const char *header_end = memchr(cursor, '\n', *len);

    if (header_end == NULL)
        return 0;

    size_t header_len = (size_t)(header_end - cursor);

    /* ignore preceding <CR> */
    if (header_len > 0 && cursor[header_len - 1] == '\r')
        header_len--;

    return header_len;
}
