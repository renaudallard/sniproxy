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

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <strings.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* 1 for yes, true or on, 0 for no, false or off, in any case, and -1 for
 * anything else. */
static inline int
parse_boolean(const char *value) {
    static const char *const true_words[] = { "yes", "true", "on" };
    static const char *const false_words[] = { "no", "false", "off" };

    for (size_t i = 0; i < sizeof(true_words) / sizeof(true_words[0]); i++) {
        if (strcasecmp(value, true_words[i]) == 0)
            return 1;
        if (strcasecmp(value, false_words[i]) == 0)
            return 0;
    }

    return -1;
}

#if !defined(HAVE_REALLOCARRAY) && !defined(HAVE_BSD_STDLIB_H)
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
static inline void *
sniproxy_reallocarray(void *ptr, size_t nmemb, size_t size)
{
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, nmemb * size);
}
#define reallocarray sniproxy_reallocarray
#endif

#endif
