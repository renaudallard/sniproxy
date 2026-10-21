/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdlib.h> /* malloc() */
#include <string.h> /* memcpy() */
#include <strings.h> /* strncasecmp() */
#include <ctype.h> /* isblank(), isdigit() */
#include "http.h"
#include "tls.h"
#include "protocol.h"
#include "hostname_sanitize.h"
#include "http2.h"

#define SERVER_NAME_LEN 256
/* CR and LF bytes skipped ahead of a request line: four empty lines */
#define HTTP_MAX_LEADING_BLANK 8

static size_t http_max_headers = HTTP_DEFAULT_MAX_HEADERS;

void
http_set_max_headers(size_t max_headers) {
    if (max_headers == 0)
        max_headers = 1;
    http_max_headers = max_headers;
}

static int parse_http_header(const char *, size_t, char **);
static int http_host_name(char *, size_t);
static int http_token_char(char);
static const char *absolute_form_authority(const char *, size_t, size_t *);
static int http_request_may_complete(const char *, size_t, size_t);
static int get_header(const char *, size_t, const char *, size_t, char **);
static size_t next_header(const char **, size_t *);


static const char http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
    .sock_type = SOCK_STREAM,
    .request_may_complete = &http_request_may_complete,
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

    size_t preface_len = sizeof(http2_preface) - 1;

    if (data_len > 0) {
        size_t cmp_len = data_len < preface_len ? data_len : preface_len;
        if (cmp_len > 0 && memcmp(data, http2_preface, cmp_len) == 0) {
            int h2_result = parse_http2_header((const unsigned char *)data, data_len, hostname);
            if (data_len >= preface_len || h2_result != -4)
                return h2_result;
        }
    }

    /* Servers skip the empty lines a client may send ahead of the request
     * line (RFC 9112 2.2), some any run of CR and LF bytes: the request
     * line is the first one after them, or the target of an absolute-form
     * request would be read from a line that is not. A client sends one
     * such line, if any; a run of more than a few is invalid, or every read
     * adding to it would have the whole of it parsed again. */
    size_t blank = 0;
    while (data_len > 0 && (*data == '\r' || *data == '\n')) {
        if (++blank > HTTP_MAX_LEADING_BLANK)
            return -5;
        data++;
        data_len--;
    }

    /* A PROXY protocol header the client sent itself would reach the
     * backend chosen by the Host header ahead of the request; it is not
     * an HTTP request line, so the request is invalid */
    static const char proxy_v1[] = "PROXY ";
    size_t proxy_cmp = data_len < sizeof(proxy_v1) - 1 ?
            data_len : sizeof(proxy_v1) - 1;
    if (proxy_cmp > 0 && memcmp(data, proxy_v1, proxy_cmp) == 0)
        return proxy_cmp < sizeof(proxy_v1) - 1 ? -1 : -5;

    /* The request line starts with a method, a token followed by a space
     * (RFC 9112 3). The binary form of the PROXY header, or white space,
     * which some servers skip, would otherwise reach the backend, and
     * keep the target of an absolute-form request from being read */
    size_t method_len = 0;
    while (method_len < data_len && http_token_char(data[method_len]))
        method_len++;
    if (method_len == data_len)
        return -1;
    if (method_len == 0 || data[method_len] != ' ')
        return -5;

    static const char host_header[] = "Host:";
    char *host = NULL;
    result = get_header(host_header, sizeof(host_header) - 1, data, data_len, &host);
    if (result < 0 && result != -2)
        return result;
    if (result >= 0) {
        result = http_host_name(host, (size_t)result);
        if (result < 0) {
            free(host);
            return result;
        }
    }

    /* A server uses the host of an absolute-form request target and
     * ignores the Host header (RFC 9112 3.2.2), and some do so with the
     * target of a CONNECT request, so the request is routed on that host,
     * and refused when the Host header names another */
    size_t authority_len;
    const char *authority = absolute_form_authority(data, data_len,
            &authority_len);
    if (authority == NULL) {
        if (host == NULL)
            return -2;
        *hostname = host;
        return result;
    }

    if (authority_len == 0 || authority_len >= SERVER_NAME_LEN ||
            memchr(authority, '@', authority_len) != NULL) {
        free(host);
        return -5;
    }

    char *target = malloc(authority_len + 1);
    if (target == NULL) {
        free(host);
        return -4;
    }
    memcpy(target, authority, authority_len);
    target[authority_len] = '\0';

    int target_result = http_host_name(target, authority_len);
    if (target_result < 0 ||
            (host != NULL && strcmp(host, target) != 0)) {
        free(target);
        free(host);
        return target_result < 0 ? target_result : -5;
    }

    free(host);
    *hostname = target;
    return target_result;
}

/*
 * Removes the port from the host of a Host header or request target in
 * buffer, which is NUL terminated, and checks what is left.
 *
 * Returns the length of the hostname, or < -4 when it is invalid.
 */
static int
http_host_name(char *buffer, size_t hostname_len) {
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

    if (!sanitize_hostname(buffer, &hostname_len, SERVER_NAME_LEN - 1))
        return TLS_ERR_INVALID_CLIENT_HELLO;

    if (hostname_len > 0 && buffer[0] != '[' && strchr(buffer, ':') != NULL)
        return -5;

    return (int)hostname_len;
}

/* A character of a token, as RFC 9110 5.6.2 defines it */
static int
http_token_char(char c) {
    return isalnum((unsigned char)c) ||
            (c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

/*
 * Returns the authority of an absolute-form request target, as in
 * GET http://example.com/ HTTP/1.1, or of the authority-form target of a
 * CONNECT request, and its length in *len, or NULL when the request line,
 * with which data starts, has a target of another form.
 */
static const char *
absolute_form_authority(const char *data, size_t data_len, size_t *len) {
    const char *end = memchr(data, '\n', data_len);

    if (end == NULL)
        return NULL;

    /* The method, then the target after any blanks */
    const char *p = data;
    while (p < end && *p != ' ' && *p != '\t')
        p++;
    int is_connect = p - data == 7 && memcmp(data, "CONNECT", 7) == 0;
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;

    /* Servers such as Go's take the host CONNECT names as the request's
     * host, as they take that of an absolute-form target; a path is not
     * one, and they take the Host header with it */
    if (is_connect && p < end && *p != '/') {
        const char *authority = p;
        while (p < end && *p != '/' && *p != '?' && *p != '#' &&
                *p != ' ' && *p != '\t' && *p != '\r')
            p++;
        *len = (size_t)(p - authority);
        return authority;
    }

    /* A scheme, as RFC 3986 3.1 defines it, followed by :// */
    if (p == end || !isalpha((unsigned char)*p))
        return NULL;
    while (p < end && (isalnum((unsigned char)*p) ||
                *p == '+' || *p == '-' || *p == '.'))
        p++;
    if (end - p < 3 || memcmp(p, "://", 3) != 0)
        return NULL;
    p += 3;

    const char *authority = p;
    while (p < end && *p != '/' && *p != '?' && *p != '#' &&
            *p != ' ' && *p != '\t' && *p != '\r')
        p++;

    *len = (size_t)(p - authority);
    return authority;
}

/* An HTTP/1 header block only ends with a new line, so data holding none
 * cannot have completed an incomplete request. HTTP/2 frames need not hold
 * one; their parse costs little, so it is always repeated. The last parse
 * took the HTTP/2 path when what it read began as the preface did, and
 * new data that departs from the preface then ends it as well. */
static int
http_request_may_complete(const char *data, size_t data_len, size_t parsed) {
    size_t preface_len = sizeof(http2_preface) - 1;
    size_t cmp_len = parsed < preface_len ? parsed : preface_len;

    if (cmp_len > data_len)
        cmp_len = data_len;
    if (memcmp(data, http2_preface, cmp_len) == 0)
        return 1;

    return parsed < data_len &&
            memchr(data + parsed, '\n', data_len - parsed) != NULL;
}

static int
get_header(const char *header, size_t header_len, const char *data, size_t data_len, char **value) {
    size_t len;
    char *found_value = NULL;
    size_t found_len = 0;
    int found = 0;
    size_t header_count = 0;

    /* loop through headers stopping at first blank line */
    while ((len = next_header(&data, &data_len)) != 0) {
        /* Limit number of headers to prevent CPU exhaustion attacks */
        if (header_count >= http_max_headers) {
            free(found_value);
            return TLS_ERR_INVALID_CLIENT_HELLO;
        }
        header_count++;

        if (len >= header_len && strncasecmp(header, data, header_len) == 0) {
            size_t value_start = header_len;

            /* Eat leading whitespace */
            while (value_start < len && isblank((unsigned char)data[value_start]))
                value_start++;

            size_t value_len = len - value_start;

            /* And trailing whitespace, before the port is looked for */
            while (value_len > 0 &&
                    isblank((unsigned char)data[value_start + value_len - 1]))
                value_len--;

            if (value_len == 0 || value_len >= SERVER_NAME_LEN) {
                free(found_value);
                return TLS_ERR_INVALID_CLIENT_HELLO;
            }

            if (found) {
                /* Multiple host headers are not permitted */
                free(found_value);
                return TLS_ERR_INVALID_CLIENT_HELLO;
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

    if (header_end == NULL) {
        /* Incomplete header line, consume remaining bytes so
         * get_header sees data_len == 0 and returns incomplete */
        *data = cursor + *len;
        *len = 0;
        return 0;
    }

    size_t header_len = (size_t)(header_end - cursor);

    /* ignore preceding <CR> */
    if (header_len > 0 && cursor[header_len - 1] == '\r')
        header_len--;

    return header_len;
}
