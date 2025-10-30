#ifndef HTTP2_H
#define HTTP2_H

#include <stddef.h>

/* Prevent unbounded memory use when buffering HEADERS/CONTINUATION blocks. */
#define HTTP2_MAX_HEADER_BLOCK_SIZE (1U << 16)

int parse_http2_header(const unsigned char *data, size_t data_len, char **hostname);

#endif
