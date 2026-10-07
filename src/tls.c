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
/* Bounds on a ClientHello split over several records */
#define TLS_MAX_CLIENT_HELLO_LEN 65536
#define TLS_MAX_CLIENT_HELLO_RECORDS 128

static size_t tls_max_extensions = TLS_DEFAULT_MAX_EXTENSIONS;
static size_t tls_max_extension_length = TLS_DEFAULT_MAX_EXTENSION_LENGTH;


#include "util.h"
#include "sni_parse.h"


static int parse_tls_header(const char *, size_t, char **);
static int join_client_hello(const uint8_t *, size_t, size_t, uint8_t **);
static int parse_client_hello(const uint8_t *, size_t, uint8_t, uint8_t,
        char **);
static int parse_client_hello_fields(const uint8_t *, size_t, uint8_t,
        uint8_t, char **, int *);

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
    .abort_message_len = sizeof(tls_alert),
    .sock_type = SOCK_STREAM,
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

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    size_t record_remaining = len - pos;
    const uint8_t *handshake = data + pos;
    uint8_t *joined = NULL;
    int result;

    /* A handshake message may span several records (RFC 8446 5.1), its
     * 4 byte header included. Records that cannot carry a ClientHello are
     * refused rather than sent to the fallback: its version would not
     * have been checked against the -T minimum. */
    if (record_remaining < 4) {
        result = join_client_hello(data, data_len, 4, &joined);
        if (result < 0)
            return result == -5 ? TLS_ERR_UNSUPPORTED_CLIENT_HELLO : result;
        handshake = joined;
    }

    if (handshake[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        debug("Not a client hello");
        free(joined);

        return -5;
    }

    len = ((size_t)handshake[1] << 16) +
        ((size_t)handshake[2] << 8) +
        (size_t)handshake[3];
    free(joined);
    joined = NULL;

    if (len + 4 <= record_remaining)
        return parse_client_hello(data + pos, len, tls_version_major,
                tls_version_minor, hostname);

    result = join_client_hello(data, data_len, len + 4, &joined);
    if (result < 0)
        return result == -5 ? TLS_ERR_UNSUPPORTED_CLIENT_HELLO : result;

    result = parse_client_hello(joined, len, tls_version_major,
            tls_version_minor, hostname);
    free(joined);
    return result;
}

/*
 * Join the handshake records at the start of data into one buffer holding
 * the hello_len bytes of a ClientHello. All of them are checked to be
 * there before anything is copied, so that a client sending the records
 * in small pieces does not have them copied again on every read.
 * Returns 0, -1 while more is needed, -4 on malloc failure or -5 when the
 * records cannot carry a ClientHello.
 */
static int
join_client_hello(const uint8_t *data, size_t data_len, size_t hello_len,
        uint8_t **joined) {
    size_t pos = 0;
    size_t have = 0;
    size_t records = 0;

    if (hello_len > TLS_MAX_CLIENT_HELLO_LEN)
        return -5;

    while (have < hello_len) {
        if (++records > TLS_MAX_CLIENT_HELLO_RECORDS)
            return -5;
        if (data_len - pos < TLS_HEADER_LEN)
            return -1;
        if (data[pos] != TLS_HANDSHAKE_CONTENT_TYPE || data[pos + 1] != 3)
            return -5;

        size_t record_len = ((size_t)data[pos + 3] << 8) +
            (size_t)data[pos + 4];
        if (record_len == 0)
            return -5;
        if (data_len - pos - TLS_HEADER_LEN < record_len)
            return -1;

        have += MIN(record_len, hello_len - have);
        pos += TLS_HEADER_LEN + record_len;
    }

    *joined = malloc(hello_len);
    if (*joined == NULL)
        return -4;

    pos = 0;
    have = 0;
    while (have < hello_len) {
        size_t record_len = ((size_t)data[pos + 3] << 8) +
            (size_t)data[pos + 4];
        size_t take = MIN(record_len, hello_len - have);

        memcpy(*joined + have, data + pos + TLS_HEADER_LEN, take);
        have += take;
        pos += TLS_HEADER_LEN + record_len;
    }

    return 0;
}

/*
 * Parse a ClientHello handshake message, its 4 byte header included, whose
 * body is hello_len bytes long. A ClientHello found invalid before its
 * version could be checked against the -T minimum is refused, rather than
 * left for the fallback, which would accept it whatever its version.
 */
static int
parse_client_hello(const uint8_t *handshake, size_t hello_len,
        uint8_t tls_version_major, uint8_t tls_version_minor,
        char **hostname) {
    int version_checked = 0;
    int result = parse_client_hello_fields(handshake, hello_len,
            tls_version_major, tls_version_minor, hostname,
            &version_checked);

    if (result < -4 && !version_checked)
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    return result;
}

/* parse_client_hello(), which sets *version_checked once the version has
 * been checked against the -T minimum */
static int
parse_client_hello_fields(const uint8_t *handshake, size_t hello_len,
        uint8_t tls_version_major, uint8_t tls_version_minor,
        char **hostname, int *version_checked) {
    const uint8_t *body = handshake + 4;
    const uint8_t *body_end = body + hello_len;
    size_t len;

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

    /* TLS 1.3+ clients set legacy_version to 0x0303 (TLS 1.2) per RFC 8446
     * and advertise the real version via the supported_versions extension.
     * Only enforce the legacy version field when the minimum is TLS 1.2 or
     * below; for TLS 1.3+ minimums, rely on the supported_versions check. */
    int require_supported_versions = (min_client_hello_version_major > 3) ||
        (min_client_hello_version_major == 3 && min_client_hello_version_minor >= 4);

    if (!require_supported_versions &&
            (client_hello_version_major < min_client_hello_version_major ||
            (client_hello_version_major == min_client_hello_version_major &&
             client_hello_version_minor < min_client_hello_version_minor))) {
        debug("Client hello TLS version %" PRIu8 ".%" PRIu8 " is not supported.",
              client_hello_version_major, client_hello_version_minor);
        return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
    }
    if (!require_supported_versions)
        *version_checked = 1;
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
        int sv = sni_extensions_have_required_version(body, len,
                min_client_hello_version_major,
                min_client_hello_version_minor,
                tls_max_extensions);
        if (sv == TLS_ERR_UNSUPPORTED_CLIENT_HELLO)
            return sv;
        if (sv < 0)
            return sv;
        if (sv == 0)
            return TLS_ERR_UNSUPPORTED_CLIENT_HELLO;
        *version_checked = 1;
    }

    return sni_parse_extensions(body, len, hostname,
            tls_max_extensions, tls_max_extension_length);
}
