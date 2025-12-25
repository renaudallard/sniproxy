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
 * XMPP stream parser for extracting the target domain from the initial
 * stream opening. This allows proxying XMPP connections including STARTTLS.
 *
 * XMPP clients send:
 *   <?xml version='1.0'?>
 *   <stream:stream to="example.com" xmlns="jabber:client" ...>
 *
 * We extract the "to" attribute value for routing purposes.
 * The STARTTLS negotiation happens after connection is established.
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "xmpp.h"
#include "protocol.h"
#include "hostname_sanitize.h"

#define SERVER_NAME_LEN 256
#define XMPP_MAX_HEADER_LEN 4096

static int parse_xmpp_stream(const char *, size_t, char **);
static const char *find_stream_tag(const char *, size_t, size_t *);
static int extract_to_attribute(const char *, size_t, char **);

static const char xmpp_error[] =
    "<?xml version='1.0'?>"
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>"
    "<stream:error>"
    "<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
    "</stream:error>"
    "</stream:stream>";

const struct Protocol *const xmpp_protocol = &(struct Protocol){
    .name = "xmpp",
    .default_port = 5222,
    .parse_packet = &parse_xmpp_stream,
    .abort_message = xmpp_error,
    .abort_message_len = sizeof(xmpp_error) - 1,
};

/*
 * Parses an XMPP stream opening for the 'to' attribute
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No 'to' attribute found
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid XMPP stream
 */
static int
parse_xmpp_stream(const char *data, size_t data_len, char **hostname) {
    const char *stream_tag;
    size_t tag_len;

    if (hostname == NULL)
        return -3;

    if (data_len == 0)
        return -1;

    if (data_len > XMPP_MAX_HEADER_LEN)
        return -5;

    stream_tag = find_stream_tag(data, data_len, &tag_len);
    if (stream_tag == NULL) {
        /* tag_len == 1 signals error (non-stream tag found) */
        if (tag_len == 1)
            return -5;
        /* tag_len == 0 means incomplete */
        return -1;
    }

    return extract_to_attribute(stream_tag, tag_len, hostname);
}

/*
 * Find the <stream:stream or <stream tag in the data.
 * Returns pointer to start of tag content (after '<stream' or '<stream:stream')
 * and sets tag_len to the length of content until '>'.
 * Returns NULL with *tag_len = 0 for incomplete, *tag_len = 1 for error.
 */
static const char *
find_stream_tag(const char *data, size_t data_len, size_t *tag_len) {
    const char *p = data;
    const char *end = data + data_len;
    const char *tag_start = NULL;
    int in_xml_decl = 0;

    *tag_len = 0;

    while (p < end) {
        if (*p == '<') {
            if (p + 1 < end && p[1] == '?') {
                in_xml_decl = 1;
                p += 2;
                continue;
            }

            if (in_xml_decl) {
                p++;
                continue;
            }

            /* Check for <stream:stream with proper boundary */
            if ((size_t)(end - p) >= 15 &&
                strncmp(p, "<stream:stream", 14) == 0 &&
                (p[14] == ' ' || p[14] == '\t' || p[14] == '\n' ||
                 p[14] == '\r' || p[14] == '>')) {
                tag_start = p + 14;
                break;
            }

            /* Partial <stream:stream - need more data */
            if ((size_t)(end - p) < 15 &&
                strncmp(p, "<stream:stream", (size_t)(end - p)) == 0) {
                return NULL;
            }

            /* Check for <stream (without namespace prefix) with proper boundary */
            if ((size_t)(end - p) >= 8 &&
                strncmp(p, "<stream", 7) == 0 &&
                (p[7] == ' ' || p[7] == '\t' || p[7] == '\n' ||
                 p[7] == '\r' || p[7] == '>')) {
                tag_start = p + 7;
                break;
            }

            /* Partial <stream - need more data */
            if ((size_t)(end - p) < 8 &&
                strncmp(p, "<stream", (size_t)(end - p)) == 0) {
                return NULL;
            }

            /* Found a tag that is not <stream - this is an error */
            *tag_len = 1;
            return NULL;
        }

        if (in_xml_decl && *p == '?' && p + 1 < end && p[1] == '>') {
            in_xml_decl = 0;
            p += 2;
            continue;
        }

        p++;
    }

    if (tag_start == NULL)
        return NULL;

    const char *tag_end = memchr(tag_start, '>', (size_t)(end - tag_start));
    if (tag_end == NULL)
        return NULL;

    *tag_len = (size_t)(tag_end - tag_start);
    return tag_start;
}

/*
 * Extract the 'to' attribute value from the stream tag content.
 * Handles both single and double quoted values.
 */
static int
extract_to_attribute(const char *tag, size_t tag_len, char **hostname) {
    const char *p = tag;
    const char *end = tag + tag_len;
    const char *to_value = NULL;
    size_t to_len = 0;

    while (p < end) {
        while (p < end && isspace((unsigned char)*p))
            p++;

        if (p >= end)
            break;

        const char *attr_start = p;
        while (p < end && *p != '=' && !isspace((unsigned char)*p))
            p++;

        size_t attr_name_len = (size_t)(p - attr_start);

        while (p < end && isspace((unsigned char)*p))
            p++;

        if (p >= end || *p != '=')
            continue;

        p++;

        while (p < end && isspace((unsigned char)*p))
            p++;

        if (p >= end)
            break;

        char quote = *p;
        if (quote != '"' && quote != '\'')
            return -5;

        p++;
        const char *value_start = p;

        while (p < end && *p != quote)
            p++;

        if (p >= end)
            return -1;

        size_t value_len = (size_t)(p - value_start);
        p++;

        if (attr_name_len == 2 && strncmp(attr_start, "to", 2) == 0) {
            to_value = value_start;
            to_len = value_len;
            break;
        }
    }

    if (to_value == NULL || to_len == 0)
        return -2;

    if (to_len >= SERVER_NAME_LEN)
        return -5;

    char *result = malloc(to_len + 1);
    if (result == NULL)
        return -4;

    memcpy(result, to_value, to_len);
    result[to_len] = '\0';

    size_t hostname_len = to_len;
    if (!sanitize_hostname(result, &hostname_len, SERVER_NAME_LEN - 1)) {
        free(result);
        return -5;
    }

    *hostname = result;
    return (int)hostname_len;
}
