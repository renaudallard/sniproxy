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
/*
 * This is a minimal TLS implementation intended only to parse the server name
 * extension.  This was created based primarily on Wireshark dissection of a
 * TLS handshake and RFC4366.
 */
#include <stdio.h>
#include <stdlib.h> /* malloc(), calloc() */
#include <stdint.h>
#include <string.h> /* memcpy() */
#include <sys/socket.h>
#include <sys/types.h>
#include "tls.h"
#include "protocol.h"
#include "logger.h"
#include "hostname_sanitize.h"

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define CLIENT_HELLO_VERSION_RANDOM_LEN 34

static size_t tls_max_extensions = TLS_DEFAULT_MAX_EXTENSIONS;
static size_t tls_max_extension_length = TLS_DEFAULT_MAX_EXTENSION_LENGTH;

size_t
tls_get_max_extensions(void) {
    return tls_max_extensions;
}

void
tls_set_max_extensions(size_t max_extensions) {
    if (max_extensions == 0)
        max_extensions = 1;
    tls_max_extensions = max_extensions;
}

size_t
tls_get_max_extension_length(void) {
    return tls_max_extension_length;
}

void
tls_set_max_extension_length(size_t max_length) {
    if (max_length == 0)
        max_length = 1;
    tls_max_extension_length = max_length;
}

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif


static int parse_tls_header(const char *, size_t, char **);
static int parse_extensions(const uint8_t*, size_t, char **);
static int parse_server_name_extension(const uint8_t*, size_t, char **);
static int extensions_have_required_version(const uint8_t *, size_t,
        uint8_t required_major, uint8_t required_minor);
static int parse_supported_versions_extension(const uint8_t *, size_t,
        uint8_t required_major, uint8_t required_minor,
        int require_supported_versions, int *version_ok);

static uint8_t min_client_hello_version_major = 3;
static uint8_t min_client_hello_version_minor = 3;

void
tls_set_min_client_hello_version(uint8_t major, uint8_t minor)
{
    min_client_hello_version_major = major;
    min_client_hello_version_minor = minor;
}


static const char tls_alert[] = {
    0x15, /* TLS Alert */
    0x03, 0x01, /* TLS version  */
    0x00, 0x02, /* Payload length */
    0x02, 0x28, /* Fatal, handshake failure */
};

const struct Protocol *const tls_protocol = &(struct Protocol){
    .name = "tls",
    .default_port = 443,
    .parse_packet = &parse_tls_header,
    .abort_message = tls_alert,
    .abort_message_len = sizeof(tls_alert)
};


/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int
parse_tls_header(const char *data_char, size_t data_len, char **hostname) {
    const uint8_t *data = (const uint8_t *)data_char;
    uint8_t tls_content_type;
    uint8_t tls_version_major;
    uint8_t tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return -3;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1) {
        debug("Received SSL 2.0 Client Hello which can not support SNI.");
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        debug("Request did not begin with TLS handshake.");
        return -5;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        debug("Received SSL %" PRIu8 ".%" PRIu8 " handshake which can not support SNI.",
              tls_version_major, tls_version_minor);

        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    /* TLS record length */
    len = ((size_t)data[3] << 8) +
        (size_t)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    size_t record_remaining = data_len - pos;
    if (record_remaining < 4)
        return -5;

    const uint8_t *handshake = data + pos;
    if (handshake[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        debug("Not a client hello");

        return -5;
    }

    len = ((size_t)handshake[1] << 16) +
        ((size_t)handshake[2] << 8) +
        (size_t)handshake[3];

    if (len + 4 > record_remaining)
        return -5;

    const uint8_t *body = handshake + 4;
    const uint8_t *body_end = body + len;

    if ((size_t)(body_end - body) < CLIENT_HELLO_VERSION_RANDOM_LEN)
        return -5;

    uint8_t client_hello_version_major = body[0];
    uint8_t client_hello_version_minor = body[1];

    if (client_hello_version_major < 3 ||
            (client_hello_version_major == 3 && client_hello_version_minor == 0)) {
        debug("Client hello TLS version %" PRIu8 ".%" PRIu8 " cannot carry SNI, rejecting.",
              client_hello_version_major, client_hello_version_minor);
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    if (client_hello_version_major < min_client_hello_version_major ||
            (client_hello_version_major == min_client_hello_version_major &&
             client_hello_version_minor < min_client_hello_version_minor)) {
        debug("Client hello TLS version %" PRIu8 ".%" PRIu8 " is not supported.",
              client_hello_version_major, client_hello_version_minor);
        /* Treat version-too-low as an unsupported ClientHello so the caller
         * rejects the connection even if a fallback backend is configured. */
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    int require_supported_versions = (min_client_hello_version_major > 3) ||
        (min_client_hello_version_major == 3 && min_client_hello_version_minor >= 4);
    body += CLIENT_HELLO_VERSION_RANDOM_LEN;

    /* Session ID */
    if ((size_t)(body_end - body) < 1)
        return -5;
    len = (size_t)body[0];
    body += 1;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* Cipher Suites */
    if ((size_t)(body_end - body) < 2)
        return -5;
    len = ((size_t)body[0] << 8) + (size_t)body[1];
    body += 2;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    /* Compression Methods */
    if ((size_t)(body_end - body) < 1)
        return -5;
    len = (size_t)body[0];
    body += 1;
    if ((size_t)(body_end - body) < len)
        return -5;
    body += len;

    if (body == body_end && tls_version_major == 3 && tls_version_minor == 0) {
        debug("Received SSL 3.0 handshake without extensions, rejecting");
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    /* Extensions */
    if ((size_t)(body_end - body) < 2)
        return -5;
    len = ((size_t)body[0] << 8) + (size_t)body[1];
    body += 2;

    if ((size_t)(body_end - body) < len)
        return -5;

    if (require_supported_versions) {
        int sv = extensions_have_required_version(body, len,
                min_client_hello_version_major, min_client_hello_version_minor);
        if (sv == TLS_ERR_UNSUPPORTED_CLIENT_HELLO)
            return sv;
        if (sv < 0)
            return sv;
        if (sv == 0)
            return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }

    return parse_extensions(body, len, hostname);
}

static int
parse_extensions(const uint8_t *data, size_t data_len, char **hostname) {
    /* Enforce extension count before parsing to prevent resource abuse. */
    size_t ext_count = 0;
    size_t probe = 0;
    while (probe + 4 <= data_len) {
        if (ext_count++ >= tls_max_extensions) {
            debug("TLS ClientHello exceeded maximum extension count (%zu)", tls_max_extensions);
            return -5;
        }
        size_t ext_len = ((size_t)data[probe + 2] << 8) + (size_t)data[probe + 3];
        if (ext_len > data_len - probe - 4)
            return -5;
        /* Cap individual extension length to avoid pathological scanning */
        if (ext_len > tls_max_extension_length)
            return -5;
        probe += 4 + ext_len;
    }
    if (probe != data_len)
        return -5;

    size_t pos = 0;
    size_t len;

    while (pos <= data_len) {
        size_t remaining = data_len - pos;
        if (remaining < 4)
            break;

        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        if (len > remaining - 4)
            return -5;

        if (data[pos] == 0x00 && data[pos + 1] == 0x00)
            return parse_server_name_extension(data + pos + 4, len, hostname);

        if (data[pos] == 0xff && data[pos + 1] == 0x01) {
            if (len < 1)
                return -5;

            size_t renegotiated_connection_length = data[pos + 4];

            if (renegotiated_connection_length != len - 1)
                return -5;

            if (renegotiated_connection_length != 0) {
                debug("Client-initiated TLS renegotiation is not supported.");
                return TLS_ERR_CLIENT_RENEGOTIATION;
            }
        }

        pos += 4 + len;
    }

    if (pos != data_len)
        return -5;

    return -2;
}

static int
extensions_have_required_version(const uint8_t *data, size_t data_len,
        uint8_t required_major, uint8_t required_minor) {
    size_t pos = 0;
    size_t len;

    while (pos <= data_len) {
        size_t remaining = data_len - pos;
        if (remaining < 4)
            break;

        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        if (len > remaining - 4)
            return -5;

        if (data[pos] == 0x00 && data[pos + 1] == 0x2b) {
            int version_ok = 0;
            int rc = parse_supported_versions_extension(data + pos + 4, len,
                    required_major, required_minor, 1, &version_ok);
            if (rc == TLS_ERR_UNSUPPORTED_CLIENT_HELLO)
                return rc;
            if (rc < 0)
                return rc;
            return version_ok ? 1 : TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
        }

        pos += 4 + len;
    }

    return 0;
}

static int
parse_server_name_extension(const uint8_t *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos < data_len) {
        size_t remaining = data_len - pos;
        if (remaining <= 3)
            break;
        len = ((size_t)data[pos + 1] << 8) +
            (size_t)data[pos + 2];

        if (len > remaining - 3)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                if (len == 0 || len >= SERVER_NAME_LEN)
                    return -5;

                const uint8_t *hostname_bytes = data + pos + 3;
                if (memchr(hostname_bytes, '\0', len) != NULL)
                    return -5;

                size_t alloc_len = len + 1;
                *hostname = calloc(alloc_len, 1);
                if (*hostname == NULL) {
                    err("calloc() failure");
                    return -4;
                }

                memcpy(*hostname, hostname_bytes, len);

                (*hostname)[len] = '\0';

                size_t hostname_len = len;

                if (!sanitize_hostname(*hostname, &hostname_len, SERVER_NAME_LEN - 1)) {
                    free(*hostname);
                    *hostname = NULL;
                    return -5;
                }

                return (int)hostname_len;
            default:
                debug("Unknown server name extension name type: %" PRIu8,
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_supported_versions_extension(const uint8_t *data, size_t data_len,
        uint8_t required_major, uint8_t required_minor,
        int require_supported_versions, int *version_ok) {
    if (data_len < 1)
        return -5;

    size_t list_len = data[0];
    data++;
    data_len--;

    if (list_len == 0 || list_len != data_len)
        return -5;
    if ((list_len & 1) != 0)
        return -5;

    if (version_ok == NULL)
        return 0;

    uint16_t required = ((uint16_t)required_major << 8) | required_minor;

    for (size_t i = 0; i < list_len; i += 2) {
        uint16_t version = ((uint16_t)data[i] << 8) | data[i + 1];
        if (version >= required) {
            *version_ok = 1;
            break;
        }
    }

    if (require_supported_versions && !*version_ok)
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;

    return 0;
}
