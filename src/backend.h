/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * Copyright (c) 2011 Manuel Kasper <mk@neon1.net>
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
#ifndef BACKEND_H
#define BACKEND_H

#include <sys/queue.h>

#if !defined(HAVE_LIBPCRE2_8)
#error "sniproxy requires libpcre2-8"
#endif

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "address.h"

STAILQ_HEAD(Backend_head, Backend);

struct Backend {
    char *pattern;
    struct Address *address;
    int use_proxy_header;

    /* Runtime fields */
    pcre2_code *pattern_re;
    pcre2_match_data *pattern_match_data;
    char *last_lookup_name;
    size_t last_lookup_len;
    size_t last_lookup_capacity;
    int last_lookup_result;
    int last_lookup_valid;
    STAILQ_ENTRY(Backend) entries;
};

void add_backend(struct Backend_head *, struct Backend *);
int init_backend(struct Backend *);
int valid_backend(const struct Backend *);
struct Backend *lookup_backend(const struct Backend_head *, const char *, size_t);
void print_backend_config(FILE *, const struct Backend *);
void remove_backend(struct Backend_head *, struct Backend *);
struct Backend *new_backend(void);
int accept_backend_arg(struct Backend *, const char *);
void free_backend(struct Backend *);


#endif
