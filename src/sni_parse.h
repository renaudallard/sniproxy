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
 * Shared SNI extension parsing routines used by both the TLS and DTLS
 * ClientHello parsers.  These functions operate on the raw extensions
 * block that follows the cipher suites and compression methods in a
 * ClientHello message.
 */
#ifndef SNI_PARSE_H
#define SNI_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "tls.h"
#include "logger.h"
#include "hostname_sanitize.h"

#define SNI_SERVER_NAME_LEN 256

static inline int
sni_parse_server_name_extension(const uint8_t *data, size_t data_len,
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
                if (len == 0 || len >= SNI_SERVER_NAME_LEN)
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

                if (!sanitize_hostname(*hostname, &hostname_len,
                        SNI_SERVER_NAME_LEN - 1)) {
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

static inline int
sni_parse_extensions(const uint8_t *data, size_t data_len, char **hostname,
        size_t max_extensions, size_t max_extension_length) {
    size_t pos = 0;
    size_t ext_count = 0;

    while (pos < data_len) {
        size_t remaining = data_len - pos;
        if (remaining < 4)
            break;

        if (ext_count++ >= max_extensions) {
            debug("ClientHello exceeded maximum extension count (%zu)",
                    max_extensions);
            return -5;
        }

        size_t len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        if (len > remaining - 4)
            return -5;

        if (len > max_extension_length)
            return -5;

        if (data[pos] == 0x00 && data[pos + 1] == 0x00)
            return sni_parse_server_name_extension(data + pos + 4, len,
                    hostname);

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

static inline int
sni_parse_supported_versions_extension(const uint8_t *data, size_t data_len,
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

static inline int
sni_extensions_have_required_version(const uint8_t *data, size_t data_len,
        uint8_t required_major, uint8_t required_minor,
        size_t max_extensions) {
    size_t pos = 0;
    size_t len;
    size_t ext_count = 0;

    while (pos < data_len) {
        size_t remaining = data_len - pos;
        if (remaining < 4)
            break;

        if (ext_count++ >= max_extensions)
            return -5;

        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        if (len > remaining - 4)
            return -5;

        if (data[pos] == 0x00 && data[pos + 1] == 0x2b) {
            int version_ok = 0;
            int rc = sni_parse_supported_versions_extension(data + pos + 4,
                    len, required_major, required_minor, 1, &version_ok);
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

#endif /* SNI_PARSE_H */
