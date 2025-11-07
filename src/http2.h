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

/*
 * Bound total HPACK dynamic table memory consumed across all HTTP/2 connections.
 * Attackers can open numerous connections to multiply per-connection limits, so
 * enforce a global budget to prevent unbounded heap usage.
 */
#define HTTP2_MAX_AGGREGATE_DYNAMIC_TABLE_SIZE (4U << 20)

/*
 * Limit total frames parsed per connection to prevent CPU exhaustion from
 * clients sending millions of tiny frames (e.g., empty PING, SETTINGS).
 */
#define HTTP2_MAX_FRAMES_PER_CONNECTION 1000

/*
 * Limit consecutive CONTINUATION frames to prevent attackers from sending
 * HEADERS followed by thousands of 1-byte CONTINUATION frames.
 */
#define HTTP2_MAX_CONTINUATION_FRAMES 32

/*
 * Maximum frame payload size. RFC 7540 allows up to 16MB but we limit to
 * 16KB by default to prevent memory exhaustion. Clients can request larger
 * via SETTINGS but we reject frames exceeding this limit.
 */
#define HTTP2_MAX_FRAME_SIZE (16 * 1024)

int parse_http2_header(const unsigned char *data, size_t data_len, char **hostname);

#endif
