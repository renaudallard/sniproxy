#ifndef HTTP2_HUFFMAN_H
#define HTTP2_HUFFMAN_H

#include <stddef.h>

int hpack_decode_huffman(const unsigned char *data, size_t len, char **out, size_t *out_len);

#endif /* HTTP2_HUFFMAN_H */
