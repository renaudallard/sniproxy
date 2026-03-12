/*
 * Copyright (c) 2026, Renaud Allard <renaud@allard.it>
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
#include <stddef.h>
#include "health.h"
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include "resolv.h"
#include "logger.h"
#endif

static int parse_health_request(const char *, size_t, char **);

static const char health_503[] =
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n\r\n";

const struct Protocol *const health_protocol = &(struct Protocol){
    .name = "health",
    .default_port = 0,
    .parse_packet = &parse_health_request,
    .abort_message = health_503,
    .abort_message_len = sizeof(health_503) - 1,
};

/*
 * Health protocol parser: always returns -2 (no hostname) on any data.
 * The actual health response is generated in connection.c.
 */
static int
parse_health_request(const char *data, size_t len, char **hostname) {
    (void)data;
    (void)len;
    (void)hostname;
    return -2;
}

int
health_check_ok(void) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return 1;
#else
    if (!resolver_is_active())
        return 0;

    if (!logger_is_healthy())
        return 0;

    return 1;
#endif
}
