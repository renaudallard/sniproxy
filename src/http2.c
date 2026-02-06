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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include "http2.h"
#include "hostname_sanitize.h"
#include "http2_huffman.h"

#define SERVER_NAME_LEN 256
#define HTTP2_DEFAULT_DYNAMIC_TABLE_SIZE 4096

static size_t http2_max_headers = HTTP2_DEFAULT_MAX_HEADERS;
static size_t http2_max_frame_size = HTTP2_DEFAULT_MAX_FRAME_SIZE;
static size_t http2_max_frames_per_connection = HTTP2_DEFAULT_MAX_FRAMES_PER_CONNECTION;
static size_t http2_max_continuation_frames = HTTP2_DEFAULT_MAX_CONTINUATION_FRAMES;

size_t
http2_get_max_headers(void) {
    return http2_max_headers;
}

void
http2_set_max_headers(size_t max_headers) {
    if (max_headers == 0)
        max_headers = 1;
    http2_max_headers = max_headers;
}

size_t
http2_get_max_frame_size(void) {
    return http2_max_frame_size;
}

void
http2_set_max_frame_size(size_t max_size) {
    if (max_size == 0)
        max_size = 1;
    http2_max_frame_size = max_size;
}

size_t
http2_get_max_frames_per_connection(void) {
    return http2_max_frames_per_connection;
}

void
http2_set_max_frames_per_connection(size_t max_frames) {
    if (max_frames == 0)
        max_frames = 1;
    http2_max_frames_per_connection = max_frames;
}

size_t
http2_get_max_continuation_frames(void) {
    return http2_max_continuation_frames;
}

void
http2_set_max_continuation_frames(size_t max_frames) {
    if (max_frames == 0)
        max_frames = 1;
    http2_max_continuation_frames = max_frames;
}

struct hpack_entry {
    char *name;
    size_t name_len;
    char *value;
    size_t value_len;
    size_t total_size;
};

struct hpack_decoder {
    struct hpack_entry *dynamic_entries;
    size_t dynamic_count;
    size_t dynamic_capacity;
    size_t dynamic_head;      /* ring buffer start index */
    size_t dynamic_size;
    size_t max_dynamic_size;
};

struct header_block {
    unsigned char *data;
    size_t len;
    size_t cap;
    uint32_t stream_id;
    size_t continuation_count;
};

struct host_accumulator {
    char *primary;
    size_t primary_len;
};

struct hpack_table_entry {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
};

#define STATIC_TABLE_ENTRY(name_literal, value_literal) \
    { \
        name_literal, sizeof(name_literal) - 1, \
        value_literal, sizeof(value_literal) - 1 \
    }

static const struct hpack_table_entry static_table[] = {
    STATIC_TABLE_ENTRY(":authority", ""),
    STATIC_TABLE_ENTRY(":method", "GET"),
    STATIC_TABLE_ENTRY(":method", "POST"),
    STATIC_TABLE_ENTRY(":path", "/"),
    STATIC_TABLE_ENTRY(":path", "/index.html"),
    STATIC_TABLE_ENTRY(":scheme", "http"),
    STATIC_TABLE_ENTRY(":scheme", "https"),
    STATIC_TABLE_ENTRY(":status", "200"),
    STATIC_TABLE_ENTRY(":status", "204"),
    STATIC_TABLE_ENTRY(":status", "206"),
    STATIC_TABLE_ENTRY(":status", "304"),
    STATIC_TABLE_ENTRY(":status", "400"),
    STATIC_TABLE_ENTRY(":status", "404"),
    STATIC_TABLE_ENTRY(":status", "500"),
    STATIC_TABLE_ENTRY("accept-charset", ""),
    STATIC_TABLE_ENTRY("accept-encoding", "gzip, deflate"),
    STATIC_TABLE_ENTRY("accept-language", ""),
    STATIC_TABLE_ENTRY("accept-ranges", ""),
    STATIC_TABLE_ENTRY("accept", ""),
    STATIC_TABLE_ENTRY("access-control-allow-origin", ""),
    STATIC_TABLE_ENTRY("age", ""),
    STATIC_TABLE_ENTRY("allow", ""),
    STATIC_TABLE_ENTRY("authorization", ""),
    STATIC_TABLE_ENTRY("cache-control", ""),
    STATIC_TABLE_ENTRY("content-disposition", ""),
    STATIC_TABLE_ENTRY("content-encoding", ""),
    STATIC_TABLE_ENTRY("content-language", ""),
    STATIC_TABLE_ENTRY("content-length", ""),
    STATIC_TABLE_ENTRY("content-location", ""),
    STATIC_TABLE_ENTRY("content-range", ""),
    STATIC_TABLE_ENTRY("content-type", ""),
    STATIC_TABLE_ENTRY("cookie", ""),
    STATIC_TABLE_ENTRY("date", ""),
    STATIC_TABLE_ENTRY("etag", ""),
    STATIC_TABLE_ENTRY("expect", ""),
    STATIC_TABLE_ENTRY("expires", ""),
    STATIC_TABLE_ENTRY("from", ""),
    STATIC_TABLE_ENTRY("host", ""),
    STATIC_TABLE_ENTRY("if-match", ""),
    STATIC_TABLE_ENTRY("if-modified-since", ""),
    STATIC_TABLE_ENTRY("if-none-match", ""),
    STATIC_TABLE_ENTRY("if-range", ""),
    STATIC_TABLE_ENTRY("if-unmodified-since", ""),
    STATIC_TABLE_ENTRY("last-modified", ""),
    STATIC_TABLE_ENTRY("link", ""),
    STATIC_TABLE_ENTRY("location", ""),
    STATIC_TABLE_ENTRY("max-forwards", ""),
    STATIC_TABLE_ENTRY("proxy-authenticate", ""),
    STATIC_TABLE_ENTRY("proxy-authorization", ""),
    STATIC_TABLE_ENTRY("range", ""),
    STATIC_TABLE_ENTRY("referer", ""),
    STATIC_TABLE_ENTRY("refresh", ""),
    STATIC_TABLE_ENTRY("retry-after", ""),
    STATIC_TABLE_ENTRY("server", ""),
    STATIC_TABLE_ENTRY("set-cookie", ""),
    STATIC_TABLE_ENTRY("strict-transport-security", ""),
    STATIC_TABLE_ENTRY("transfer-encoding", ""),
    STATIC_TABLE_ENTRY("user-agent", ""),
    STATIC_TABLE_ENTRY("vary", ""),
    STATIC_TABLE_ENTRY("via", ""),
    STATIC_TABLE_ENTRY("www-authenticate", ""),
};

struct hpack_static_name_index {
    const char *name;
    size_t name_len;
    uint8_t first_index;
    uint8_t count;
};

#define STATIC_NAME_INDEX_ENTRY(first_idx, entry_count, literal) \
    { \
        (literal), \
        sizeof(literal) - 1, \
        (uint8_t)(first_idx), \
        (uint8_t)(entry_count) \
    }

static const struct hpack_static_name_index static_name_index[] = {
    STATIC_NAME_INDEX_ENTRY(1, 1, ":authority"),
    STATIC_NAME_INDEX_ENTRY(2, 2, ":method"),
    STATIC_NAME_INDEX_ENTRY(4, 2, ":path"),
    STATIC_NAME_INDEX_ENTRY(6, 2, ":scheme"),
    STATIC_NAME_INDEX_ENTRY(8, 7, ":status"),
    STATIC_NAME_INDEX_ENTRY(19, 1, "accept"),
    STATIC_NAME_INDEX_ENTRY(15, 1, "accept-charset"),
    STATIC_NAME_INDEX_ENTRY(16, 1, "accept-encoding"),
    STATIC_NAME_INDEX_ENTRY(17, 1, "accept-language"),
    STATIC_NAME_INDEX_ENTRY(18, 1, "accept-ranges"),
    STATIC_NAME_INDEX_ENTRY(20, 1, "access-control-allow-origin"),
    STATIC_NAME_INDEX_ENTRY(21, 1, "age"),
    STATIC_NAME_INDEX_ENTRY(22, 1, "allow"),
    STATIC_NAME_INDEX_ENTRY(23, 1, "authorization"),
    STATIC_NAME_INDEX_ENTRY(24, 1, "cache-control"),
    STATIC_NAME_INDEX_ENTRY(25, 1, "content-disposition"),
    STATIC_NAME_INDEX_ENTRY(26, 1, "content-encoding"),
    STATIC_NAME_INDEX_ENTRY(27, 1, "content-language"),
    STATIC_NAME_INDEX_ENTRY(28, 1, "content-length"),
    STATIC_NAME_INDEX_ENTRY(29, 1, "content-location"),
    STATIC_NAME_INDEX_ENTRY(30, 1, "content-range"),
    STATIC_NAME_INDEX_ENTRY(31, 1, "content-type"),
    STATIC_NAME_INDEX_ENTRY(32, 1, "cookie"),
    STATIC_NAME_INDEX_ENTRY(33, 1, "date"),
    STATIC_NAME_INDEX_ENTRY(34, 1, "etag"),
    STATIC_NAME_INDEX_ENTRY(35, 1, "expect"),
    STATIC_NAME_INDEX_ENTRY(36, 1, "expires"),
    STATIC_NAME_INDEX_ENTRY(37, 1, "from"),
    STATIC_NAME_INDEX_ENTRY(38, 1, "host"),
    STATIC_NAME_INDEX_ENTRY(39, 1, "if-match"),
    STATIC_NAME_INDEX_ENTRY(40, 1, "if-modified-since"),
    STATIC_NAME_INDEX_ENTRY(41, 1, "if-none-match"),
    STATIC_NAME_INDEX_ENTRY(42, 1, "if-range"),
    STATIC_NAME_INDEX_ENTRY(43, 1, "if-unmodified-since"),
    STATIC_NAME_INDEX_ENTRY(44, 1, "last-modified"),
    STATIC_NAME_INDEX_ENTRY(45, 1, "link"),
    STATIC_NAME_INDEX_ENTRY(46, 1, "location"),
    STATIC_NAME_INDEX_ENTRY(47, 1, "max-forwards"),
    STATIC_NAME_INDEX_ENTRY(48, 1, "proxy-authenticate"),
    STATIC_NAME_INDEX_ENTRY(49, 1, "proxy-authorization"),
    STATIC_NAME_INDEX_ENTRY(50, 1, "range"),
    STATIC_NAME_INDEX_ENTRY(51, 1, "referer"),
    STATIC_NAME_INDEX_ENTRY(52, 1, "refresh"),
    STATIC_NAME_INDEX_ENTRY(53, 1, "retry-after"),
    STATIC_NAME_INDEX_ENTRY(54, 1, "server"),
    STATIC_NAME_INDEX_ENTRY(55, 1, "set-cookie"),
    STATIC_NAME_INDEX_ENTRY(56, 1, "strict-transport-security"),
    STATIC_NAME_INDEX_ENTRY(57, 1, "transfer-encoding"),
    STATIC_NAME_INDEX_ENTRY(58, 1, "user-agent"),
    STATIC_NAME_INDEX_ENTRY(59, 1, "vary"),
    STATIC_NAME_INDEX_ENTRY(60, 1, "via"),
    STATIC_NAME_INDEX_ENTRY(61, 1, "www-authenticate"),
};

#define STATIC_NAME_INDEX_COUNT (sizeof(static_name_index) / sizeof(static_name_index[0]))

static int
compare_static_name(const char *name, size_t name_len,
        const struct hpack_static_name_index *entry) {
    if (name_len < entry->name_len)
        return -1;
    if (name_len > entry->name_len)
        return 1;
    return memcmp(name, entry->name, name_len);
}

static const struct hpack_static_name_index *
hpack_lookup_static_name(const char *name, size_t name_len) {
    if (name == NULL)
        return NULL;

    if (name_len == static_table[0].name_len &&
            memcmp(name, static_table[0].name, name_len) == 0)
        return &static_name_index[0];

    if (STATIC_NAME_INDEX_COUNT <= 1)
        return NULL;

    size_t low = 1;
    size_t high = STATIC_NAME_INDEX_COUNT - 1;

    while (low <= high) {
        size_t mid = low + (high - low) / 2;
        const struct hpack_static_name_index *entry = &static_name_index[mid];
        int cmp = compare_static_name(name, name_len, entry);
        if (cmp == 0)
            return entry;
        if (cmp < 0) {
            if (mid == 0)
                break;
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }

    return NULL;
}

#define HPACK_STATIC_INDEX_AUTHORITY 1
#define HPACK_STATIC_INDEX_HOST 38

#define STATIC_TABLE_LENGTH (sizeof(static_table) / sizeof(static_table[0]))

static void hpack_decoder_init(struct hpack_decoder *decoder);
static void hpack_decoder_free(struct hpack_decoder *decoder);
static int hpack_set_dynamic_size(struct hpack_decoder *decoder, size_t size);
static int hpack_add_entry(struct hpack_decoder *decoder, const char *name, size_t name_len, const char *value, size_t value_len);
static int hpack_get_indexed(const struct hpack_decoder *decoder, size_t index,
        const char **name, size_t *name_len,
        const char **value, size_t *value_len);
static int hpack_get_name(const struct hpack_decoder *decoder, size_t index,
        const char **name, size_t *name_len);

static int decode_integer(const unsigned char *data, size_t data_len, unsigned int prefix,
        size_t *value, size_t *consumed);
static int hpack_decode_string(const unsigned char *data, size_t data_len, size_t *consumed,
        char **out, size_t *out_len);

static size_t hpack_global_dynamic_usage;

static int hpack_global_try_reserve(size_t size);
static void hpack_global_release(size_t size);
static void hpack_drop_last_entry(struct hpack_decoder *decoder);

static void header_block_reset(struct header_block *block);
static void header_block_free(struct header_block *block);
static int header_block_append(struct header_block *block, const unsigned char *data, size_t len);
static const struct hpack_static_name_index *hpack_lookup_static_name(const char *, size_t);

static int
hpack_global_try_reserve(size_t size) {
    if (size > HTTP2_MAX_AGGREGATE_DYNAMIC_TABLE_SIZE)
        return 0;

    if (hpack_global_dynamic_usage > HTTP2_MAX_AGGREGATE_DYNAMIC_TABLE_SIZE - size)
        return 0;

    hpack_global_dynamic_usage += size;
    return 1;
}

static void
hpack_global_release(size_t size) {
    if (size > hpack_global_dynamic_usage)
        hpack_global_dynamic_usage = 0;
    else
        hpack_global_dynamic_usage -= size;
}

static void
hpack_drop_last_entry(struct hpack_decoder *decoder) {
    if (decoder == NULL || decoder->dynamic_count == 0)
        return;

    size_t tail = (decoder->dynamic_head + decoder->dynamic_count - 1) % decoder->dynamic_capacity;
    struct hpack_entry *entry = &decoder->dynamic_entries[tail];

    if (decoder->dynamic_size >= entry->total_size)
        decoder->dynamic_size -= entry->total_size;
    else
        decoder->dynamic_size = 0;

    hpack_global_release(entry->total_size);
    free(entry->name);
    free(entry->value);
    decoder->dynamic_count--;
}

static int decode_header_block(struct hpack_decoder *decoder,
        const unsigned char *data, size_t len,
        struct host_accumulator *hosts);

static int append_hostname_if_needed(struct host_accumulator *hosts,
        const char *name, size_t name_len,
        const char *value, size_t value_len);

static int parse_frames(const unsigned char *data, size_t data_len, char **hostname);

int
parse_http2_header(const unsigned char *data, size_t data_len, char **hostname) {
    static const unsigned char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t preface_len = sizeof(preface) - 1;

    if (hostname == NULL)
        return -3;

    size_t cmp_len = data_len < preface_len ? data_len : preface_len;
    if (memcmp(data, preface, cmp_len) != 0)
        return -4;

    if (data_len < preface_len)
        return -1;

    return parse_frames(data + preface_len, data_len - preface_len, hostname);
}

static int
parse_frames(const unsigned char *data, size_t data_len, char **hostname) {
    struct hpack_decoder decoder;
    hpack_decoder_init(&decoder);
    struct header_block block = { NULL, 0, 0, 0, 0 };
    struct host_accumulator hosts = { NULL, 0 };

    size_t pos = 0;
    int result = -1;
    size_t frame_count = 0;

    while (pos <= data_len) {
        size_t remaining = data_len - pos;
        if (remaining < 9)
            break;

        if (++frame_count > http2_max_frames_per_connection) {
            result = -4;
            goto done;
        }

        uint32_t length = ((uint32_t)data[pos] << 16) |
                          ((uint32_t)data[pos + 1] << 8) |
                          data[pos + 2];
        unsigned char type = data[pos + 3];
        unsigned char flags = data[pos + 4];
        uint32_t stream_id = ((uint32_t)(data[pos + 5] & 0x7F) << 24) |
                             ((uint32_t)data[pos + 6] << 16) |
                             ((uint32_t)data[pos + 7] << 8) |
                             data[pos + 8];
        pos += 9;

        if (length > http2_max_frame_size) {
            result = -4;
            goto done;
        }

        if (length > data_len - pos) {
            result = -1;
            goto done;
        }

        const unsigned char *payload = data + pos;

        switch (type) {
            case 0x1: { /* HEADERS */
                size_t idx = 0;
                unsigned char pad_length = 0;

                if (flags & 0x08) {
                    if (length == 0) {
                        result = -4;
                        goto done;
                    }
                    pad_length = payload[idx++];
                    if (pad_length > length - idx) {
                        result = -4;
                        goto done;
                    }
                }

                if (flags & 0x20) {
                    if (length - idx < 5) {
                        result = -4;
                        goto done;
                    }
                    idx += 5;
                }

                if (length < idx)
                    idx = length;

                size_t fragment_len = length - idx;
                if (pad_length > fragment_len) {
                    result = -4;
                    goto done;
                }
                fragment_len -= pad_length;

                if (fragment_len > 0) {
                    if (block.stream_id != 0 && block.stream_id != stream_id) {
                        result = -4;
                        goto done;
                    }
                    block.stream_id = stream_id;
                    block.continuation_count = 0;
                    if (!header_block_append(&block, payload + idx, fragment_len)) {
                        result = -4;
                        goto done;
                    }
                }

                if (flags & 0x04) {
                    result = decode_header_block(&decoder, block.data, block.len, &hosts);
                    if (result < 0)
                        goto done;
                    if (hosts.primary != NULL) {
                        result = (int)hosts.primary_len;
                        goto done;
                    }
                    header_block_reset(&block);
                }
                break;
            }
            case 0x9: { /* CONTINUATION */
                if (block.stream_id == 0 || block.stream_id != stream_id) {
                    result = -4;
                    goto done;
                }
                if (++block.continuation_count > http2_max_continuation_frames) {
                    result = -4;
                    goto done;
                }
                if (length > 0) {
                    if (!header_block_append(&block, payload, length)) {
                        result = -4;
                        goto done;
                    }
                }
                if (flags & 0x04) {
                    result = decode_header_block(&decoder, block.data, block.len, &hosts);
                    if (result < 0)
                        goto done;
                    if (hosts.primary != NULL) {
                        result = (int)hosts.primary_len;
                        goto done;
                    }
                    header_block_reset(&block);
                }
                break;
            }
            case 0x4: /* SETTINGS */
                if (!(flags & 0x1)) {
                    if (length % 6 != 0) {
                        result = -4;
                        goto done;
                    }
                    for (size_t i = 0; i < length; i += 6) {
                        uint16_t identifier = ((uint16_t)payload[i] << 8) | payload[i + 1];
                        uint32_t value = ((uint32_t)payload[i + 2] << 24) |
                                         ((uint32_t)payload[i + 3] << 16) |
                                         ((uint32_t)payload[i + 4] << 8) |
                                         payload[i + 5];
                        if (identifier == 0x1) {
                            if (!hpack_set_dynamic_size(&decoder, value)) {
                                result = -4;
                                goto done;
                            }
                        }
                    }
                }
                break;
            default:
                break;
        }

        pos += length;
    }

    result = -2;

 done:
    if (result >= 0 && hosts.primary != NULL) {
        *hostname = hosts.primary;
        hosts.primary = NULL;
    }

    if (hosts.primary != NULL)
        free(hosts.primary);

    header_block_free(&block);
    hpack_decoder_free(&decoder);

    return result;
}

static int
decode_header_block(struct hpack_decoder *decoder,
        const unsigned char *data, size_t len,
        struct host_accumulator *hosts) {
    size_t pos = 0;
    size_t decoded_budget = HTTP2_MAX_HEADER_BLOCK_SIZE;
    size_t header_count = 0;

    while (pos < len) {
        unsigned char byte = data[pos];

        /* Dynamic table size updates don't count as headers */
        if ((byte & 0xE0) != 0x20) {
            if (++header_count > http2_max_headers)
                return -4;
        }

        if (byte & 0x80) { /* Indexed header field */
            size_t index;
            size_t consumed;
            if (decode_integer(data + pos, len - pos, 7, &index, &consumed) < 0)
                return -1;

            const char *name = NULL, *value = NULL;
            size_t name_len = 0, value_len = 0;
            if (!hpack_get_indexed(decoder, index, &name, &name_len, &value, &value_len))
                return -4;

            if (append_hostname_if_needed(hosts, name, name_len, value, value_len) < 0)
                return -4;

            pos += consumed;
            continue;
        }

        if ((byte & 0xE0) == 0x20) { /* Dynamic table size update */
            size_t new_size;
            size_t consumed;
            if (decode_integer(data + pos, len - pos, 5, &new_size, &consumed) < 0)
                return -1;
            if (!hpack_set_dynamic_size(decoder, new_size))
                return -4;
            pos += consumed;
            continue;
        }

        int add_to_table = ((byte & 0xC0) == 0x40);
        size_t prefix = add_to_table ? 6 : 4;
        size_t name_index;
        size_t consumed;
        if (decode_integer(data + pos, len - pos, prefix, &name_index, &consumed) < 0)
            return -1;
        pos += consumed;

        char *name = NULL;
        size_t name_len;
        if (name_index == 0) {
            size_t str_consumed;
            if (hpack_decode_string(data + pos, len - pos, &str_consumed, &name, &name_len) < 0)
                return -4;
            if (name_len > decoded_budget) {
                free(name);
                return -4;
            }
            decoded_budget -= name_len;
            pos += str_consumed;
        } else {
            const char *existing_name;
            size_t existing_len;
            if (!hpack_get_name(decoder, name_index, &existing_name, &existing_len))
                return -4;
            if (existing_len > SIZE_MAX - 1)
                return -4;
            if (existing_len > decoded_budget)
                return -4;

            name = malloc(existing_len + 1);
            if (name == NULL)
                return -4;
            memcpy(name, existing_name, existing_len);
            name[existing_len] = '\0';
            name_len = existing_len;
            decoded_budget -= name_len;
        }

        char *value = NULL;
        size_t value_len;
        size_t str_consumed;
        if (hpack_decode_string(data + pos, len - pos, &str_consumed, &value, &value_len) < 0) {
            free(name);
            return -4;
        }
        if (value_len > decoded_budget) {
            free(name);
            free(value);
            return -4;
        }
        pos += str_consumed;
        decoded_budget -= value_len;

        if (append_hostname_if_needed(hosts, name, name_len, value, value_len) < 0) {
            free(name);
            free(value);
            return -4;
        }

        if (add_to_table) {
            if (!hpack_add_entry(decoder, name, name_len, value, value_len)) {
                free(name);
                free(value);
                return -4;
            }
        }

        free(name);
        free(value);
    }

    return 0;
}

static int
append_hostname_if_needed(struct host_accumulator *hosts,
        const char *name, size_t name_len,
        const char *value, size_t value_len) {
    if (name == NULL || value == NULL)
        return 0;

    if (name_len == 0 || value_len == 0)
        return 0;

    int is_host = 0;
    const struct hpack_table_entry *authority_entry =
            &static_table[HPACK_STATIC_INDEX_AUTHORITY - 1];
    const struct hpack_table_entry *host_entry =
            &static_table[HPACK_STATIC_INDEX_HOST - 1];

    if (name == authority_entry->name ||
            (name_len == authority_entry->name_len &&
             memcmp(name, authority_entry->name, name_len) == 0)) {
        is_host = 1;
    } else if (name == host_entry->name) {
        is_host = 1;
    } else {
        const struct hpack_static_name_index *static_name =
                hpack_lookup_static_name(name, name_len);
        if (static_name != NULL &&
                (static_name->first_index == HPACK_STATIC_INDEX_AUTHORITY ||
                 static_name->first_index == HPACK_STATIC_INDEX_HOST))
            is_host = 1;
    }

    if (!is_host)
        return 0;

    if (value_len >= SERVER_NAME_LEN)
        return -4;

    if (value_len > SIZE_MAX - 1)
        return -4;

    char *buffer = malloc(value_len + 1);
    if (buffer == NULL)
        return -4;

    memcpy(buffer, value, value_len);
    buffer[value_len] = '\0';

    size_t len = value_len;

    char *port = strrchr(buffer, ':');
    if (port != NULL) {
        int digits_only = 1;

        for (char *p = port + 1; *p != '\0'; p++)
            if (!isdigit((unsigned char)*p)) {
                digits_only = 0;
                break;
            }

        if (digits_only) {
            if (port > buffer && port[-1] == ':') {
                digits_only = 0;
            } else if (buffer[0] != '[') {
                char *first_colon = strchr(buffer, ':');
                if (first_colon != NULL && first_colon != port)
                    digits_only = 0;
            }
        }

        if (digits_only) {
            *port = '\0';
            len = (size_t)(port - buffer);
        }
    }

    if (len == 0)
        len = strlen(buffer);

    if (!sanitize_hostname(buffer, &len, SERVER_NAME_LEN - 1)) {
        free(buffer);
        return -4;
    }

    if (len > 0 && buffer[0] != '[' && memchr(buffer, ':', len) != NULL) {
        free(buffer);
        return -4;
    }

    if (hosts->primary == NULL) {
        hosts->primary = buffer;
        hosts->primary_len = len;
        return 0;
    }

    if (len != hosts->primary_len || memcmp(buffer, hosts->primary, len) != 0) {
        free(buffer);
        return -4;
    }

    free(buffer);
    return 0;
}

static void
hpack_decoder_init(struct hpack_decoder *decoder) {
    decoder->dynamic_entries = NULL;
    decoder->dynamic_count = 0;
    decoder->dynamic_capacity = 0;
    decoder->dynamic_head = 0;
    decoder->dynamic_size = 0;
    decoder->max_dynamic_size = HTTP2_DEFAULT_DYNAMIC_TABLE_SIZE;
}

static void
hpack_decoder_free(struct hpack_decoder *decoder) {
    if (decoder == NULL)
        return;

    while (decoder->dynamic_count > 0)
        hpack_drop_last_entry(decoder);

    free(decoder->dynamic_entries);
    decoder->dynamic_entries = NULL;
    decoder->dynamic_capacity = 0;
    decoder->dynamic_head = 0;
    decoder->dynamic_size = 0;
}

static int
hpack_set_dynamic_size(struct hpack_decoder *decoder, size_t size) {
    if (size > HTTP2_MAX_DYNAMIC_TABLE_SIZE)
        return 0;

    decoder->max_dynamic_size = size;

    while (decoder->dynamic_size > decoder->max_dynamic_size && decoder->dynamic_count > 0)
        hpack_drop_last_entry(decoder);

    return 1;
}

static int
hpack_add_entry(struct hpack_decoder *decoder, const char *name, size_t name_len, const char *value, size_t value_len) {
    if (name_len > SIZE_MAX - value_len)
        return 0;

    size_t combined_len = name_len + value_len;
    assert(combined_len >= name_len && combined_len >= value_len);

    if (combined_len > SIZE_MAX - 32)
        return 0;

    size_t entry_size = combined_len + 32;
    assert(entry_size >= combined_len && entry_size >= 32);

    if (entry_size > decoder->max_dynamic_size) {
        while (decoder->dynamic_count > 0)
            hpack_drop_last_entry(decoder);
        return 1;
    }

    while (decoder->dynamic_size + entry_size > decoder->max_dynamic_size && decoder->dynamic_count > 0)
        hpack_drop_last_entry(decoder);

    if (decoder->dynamic_count == decoder->dynamic_capacity) {
        size_t new_cap = decoder->dynamic_capacity == 0 ? 8 : decoder->dynamic_capacity;

        if (new_cap > SIZE_MAX / 2)
            return 0;

        new_cap *= 2;

        if (new_cap > SIZE_MAX / sizeof(struct hpack_entry))
            return 0;

        size_t alloc_size = new_cap * sizeof(struct hpack_entry);
        struct hpack_entry *tmp = malloc(alloc_size);
        if (tmp == NULL)
            return 0;

        /* Linearize ring buffer into new allocation */
        for (size_t i = 0; i < decoder->dynamic_count; i++) {
            size_t src = (decoder->dynamic_head + i) % decoder->dynamic_capacity;
            tmp[i] = decoder->dynamic_entries[src];
        }
        free(decoder->dynamic_entries);
        decoder->dynamic_entries = tmp;
        decoder->dynamic_head = 0;
        decoder->dynamic_capacity = new_cap;
    }

    if (name_len > SIZE_MAX - 1 || value_len > SIZE_MAX - 1)
        return 0;

    if (!hpack_global_try_reserve(entry_size))
        return 0;

    char *new_name = malloc(name_len + 1);
    char *new_value = malloc(value_len + 1);
    if (new_name == NULL || new_value == NULL) {
        free(new_name);
        free(new_value);
        hpack_global_release(entry_size);
        return 0;
    }

    memcpy(new_name, name, name_len);
    new_name[name_len] = '\0';
    memcpy(new_value, value, value_len);
    new_value[value_len] = '\0';

    /* Insert at front of ring buffer */
    decoder->dynamic_head = decoder->dynamic_head == 0
        ? decoder->dynamic_capacity - 1
        : decoder->dynamic_head - 1;

    struct hpack_entry *entry = &decoder->dynamic_entries[decoder->dynamic_head];
    entry->name = new_name;
    entry->name_len = name_len;
    entry->value = new_value;
    entry->value_len = value_len;
    entry->total_size = entry_size;

    decoder->dynamic_count++;
    decoder->dynamic_size += entry_size;

    return 1;
}

static int
hpack_get_indexed(const struct hpack_decoder *decoder, size_t index,
        const char **name, size_t *name_len,
        const char **value, size_t *value_len) {
    if (index == 0)
        return 0;

    if (index <= STATIC_TABLE_LENGTH) {
        const struct hpack_table_entry *entry = &static_table[index - 1];
        if (name != NULL) {
            *name = entry->name;
            *name_len = entry->name_len;
        }
        if (value != NULL) {
            *value = entry->value;
            *value_len = entry->value_len;
        }
        return 1;
    }

    size_t dynamic_index = index - STATIC_TABLE_LENGTH - 1;
    if (dynamic_index >= decoder->dynamic_count)
        return 0;

    size_t ring_index = (decoder->dynamic_head + dynamic_index) % decoder->dynamic_capacity;
    const struct hpack_entry *entry = &decoder->dynamic_entries[ring_index];
    if (name != NULL) {
        *name = entry->name;
        *name_len = entry->name_len;
    }
    if (value != NULL) {
        *value = entry->value;
        *value_len = entry->value_len;
    }
    return 1;
}

static int
hpack_get_name(const struct hpack_decoder *decoder, size_t index,
        const char **name, size_t *name_len) {
    return hpack_get_indexed(decoder, index, name, name_len, NULL, NULL);
}

static int
decode_integer(const unsigned char *data, size_t data_len, unsigned int prefix,
        size_t *value, size_t *consumed) {
    if (data_len == 0 || prefix >= 8)
        return -1;

    unsigned char mask = (unsigned char)((1u << prefix) - 1u);
    size_t result = data[0] & mask;
    size_t idx = 1;

    if (result == mask) {
        size_t shift = 0;
        const size_t shift_limit = sizeof(size_t) * CHAR_BIT;
        do {
            if (idx >= data_len)
                return -1;
            unsigned char byte = data[idx++];
            size_t chunk = (size_t)(byte & 0x7F);

            if (shift >= shift_limit)
                return -1;
            if (chunk > (SIZE_MAX >> shift))
                return -1;
            size_t addend = chunk << shift;
            if (result > SIZE_MAX - addend)
                return -1;

            result += addend;

            if (!(byte & 0x80))
                break;

            if (shift_limit - shift < 7)
                shift = shift_limit;
            else
                shift += 7;
        } while (1);
    }

    *value = result;
    *consumed = idx;
    return 0;
}

static int
hpack_decode_string(const unsigned char *data, size_t data_len, size_t *consumed,
        char **out, size_t *out_len) {
    if (data_len == 0)
        return -1;

    int huffman = (data[0] & 0x80) != 0;
    size_t length;
    size_t used;
    if (decode_integer(data, data_len, 7, &length, &used) < 0)
        return -1;

    if (length > SIZE_MAX - 1)
        return -1;

    if (length > data_len - used)
        return -1;

    if (huffman) {
        if (hpack_decode_huffman(data + used, length, out, out_len) < 0)
            return -1;
    } else {
        char *buf = malloc(length + 1);
        if (buf == NULL)
            return -1;
        memcpy(buf, data + used, length);
        buf[length] = '\0';
        *out = buf;
        *out_len = length;
    }

    *consumed = used + length;
    return 0;
}

static int
header_block_append(struct header_block *block, const unsigned char *data, size_t len) {
    if (len == 0)
        return 1;

    if (len > SIZE_MAX - block->len)
        return 0;

    size_t needed = block->len + len;

    if (needed > HTTP2_MAX_HEADER_BLOCK_SIZE)
        return 0;

    if (needed > block->cap) {
        size_t new_cap = block->cap == 0 ? 256 : block->cap;
        while (new_cap < needed) {
            if (new_cap > SIZE_MAX / 2)
                return 0;
            new_cap *= 2;
        }
        unsigned char *tmp = realloc(block->data, new_cap);
        if (tmp == NULL)
            return 0;
        block->data = tmp;
        block->cap = new_cap;
    }

    memcpy(block->data + block->len, data, len);
    block->len += len;

    return 1;
}

static void
header_block_reset(struct header_block *block) {
    block->len = 0;
    block->stream_id = 0;
    block->continuation_count = 0;
}

static void
header_block_free(struct header_block *block) {
    if (block == NULL)
        return;
    free(block->data);
    block->data = NULL;
    block->cap = 0;
    block->len = 0;
    block->stream_id = 0;
}
