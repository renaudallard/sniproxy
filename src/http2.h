#ifndef HTTP2_H
#define HTTP2_H

#include <stddef.h>

/* Prevent unbounded memory use when buffering HEADERS/CONTINUATION blocks. */
#define HTTP2_MAX_HEADER_BLOCK_SIZE (1U << 16)

/*
 * Limit the total amount of memory the dynamic table can consume while decoding
 * HPACK headers.  Clients are allowed to advertise very large table sizes via
 * SETTINGS frames, but honouring those values would allow an attacker to force
 * the proxy to allocate large amounts of memory.  Cap the accepted value so we
 * can safely bound allocations.
 */
#define HTTP2_MAX_DYNAMIC_TABLE_SIZE (1U << 16)

int parse_http2_header(const unsigned char *data, size_t data_len, char **hostname);

#endif
