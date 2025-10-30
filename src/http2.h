#ifndef HTTP2_H
#define HTTP2_H

#include <stddef.h>

int parse_http2_header(const unsigned char *data, size_t data_len, char **hostname);

#endif
