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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/queue.h>
#include <assert.h>
#include "backend.h"
#include "address.h"
#include "logger.h"

#define BACKEND_REGEX_DEPTH_LIMIT 1000

#define BACKEND_REGEX_MATCH_LIMIT 10000
#define BACKEND_REGEX_MATCH_BASE 256
#define BACKEND_REGEX_MATCH_PER_CHAR 32

static const char *backend_config_options(const struct Backend *);
static uint32_t backend_regex_match_limit_for_len(size_t len);
static int backend_cached_result(const struct Backend *, const char *, size_t, int *);
static void backend_store_match_cache(struct Backend *, const char *, size_t, int);

static uint32_t
backend_regex_match_limit_for_len(size_t len) {
    uint64_t limit = BACKEND_REGEX_MATCH_BASE;

    if (len > 0) {
        uint64_t extra = (uint64_t)len * BACKEND_REGEX_MATCH_PER_CHAR;
        if (extra > UINT32_MAX)
            extra = UINT32_MAX;
        limit += extra;
    }

    if (limit > BACKEND_REGEX_MATCH_LIMIT)
        limit = BACKEND_REGEX_MATCH_LIMIT;

    if (limit < BACKEND_REGEX_MATCH_BASE)
        limit = BACKEND_REGEX_MATCH_BASE;

    return (uint32_t)limit;
}

static int
backend_cached_result(const struct Backend *backend, const char *name, size_t len, int *matched) {
    if (backend == NULL || !backend->last_lookup_valid)
        return 0;

    if (backend->last_lookup_len != len)
        return 0;

    if (len > 0) {
        if (backend->last_lookup_name == NULL)
            return 0;
        if (memcmp(backend->last_lookup_name, name, len) != 0)
            return 0;
    }

    if (matched != NULL)
        *matched = backend->last_lookup_result;
    return 1;
}

static void
backend_store_match_cache(struct Backend *backend, const char *name, size_t len, int matched) {
    if (backend == NULL)
        return;

    if (len > 0) {
        if (len >= SIZE_MAX) {
            backend->last_lookup_valid = 0;
            return;
        }
        size_t needed = len + 1;
        if (needed > backend->last_lookup_capacity) {
            char *tmp = realloc(backend->last_lookup_name, needed);
            if (tmp == NULL) {
                backend->last_lookup_valid = 0;
                return;
            }
            backend->last_lookup_name = tmp;
            backend->last_lookup_capacity = needed;
        }
        if (backend->last_lookup_name != NULL && name != NULL) {
            memcpy(backend->last_lookup_name, name, len);
            backend->last_lookup_name[len] = '\0';
        }
    } else if (backend->last_lookup_name != NULL) {
        backend->last_lookup_name[0] = '\0';
    }

    backend->last_lookup_len = len;
    backend->last_lookup_result = matched ? 1 : 0;
    backend->last_lookup_valid = 1;
}


static pcre2_match_context *backend_match_ctx;
static int backend_match_ctx_registered;
static void backend_regex_runtime_init(void);
static void backend_regex_cleanup(void);


struct Backend *
new_backend(void) {
    struct Backend *backend;

    backend = calloc(1, sizeof(struct Backend));
    if (backend == NULL) {
        err("malloc");
        return NULL;
    }

    backend->pattern = NULL;
    backend->address = NULL;
    backend->use_proxy_header = 0;
    backend->pattern_re = NULL;
    backend->pattern_match_data = NULL;
    backend->last_lookup_name = NULL;
    backend->last_lookup_len = 0;
    backend->last_lookup_capacity = 0;
    backend->last_lookup_result = 0;
    backend->last_lookup_valid = 0;

    return backend;
}

int
accept_backend_arg(struct Backend *backend, const char *arg) {
    if (backend->pattern == NULL) {
        backend->pattern = strdup(arg);
        if (backend->pattern == NULL) {
            err("strdup failed");
            return -1;
        }
    } else if (backend->address == NULL) {

        backend->address = new_address(arg);
        if (backend->address == NULL) {
            err("invalid address: %s", arg);
            return -1;
        }
    } else if (address_port(backend->address) == 0 && is_numeric(arg)) {
        if (!address_set_port_str(backend->address, arg)) {
            err("Invalid port: %s", arg);
            return -1;
        }
    } else if (backend->use_proxy_header == 0 &&
        strcasecmp(arg, "proxy_protocol") == 0) {
        backend->use_proxy_header = 1;
    } else {
        err("Unexpected table backend argument: %s", arg);
        return -1;
    }

    return 1;
}

void
add_backend(struct Backend_head *backends, struct Backend *backend) {
    STAILQ_INSERT_TAIL(backends, backend, entries);
}

int
init_backend(struct Backend *backend) {
    if (backend == NULL || backend->pattern == NULL || backend->address == NULL) {
        err("Incomplete backend configuration");
        return 0;
    }

    if (backend->pattern_re == NULL) {

        int reerr;
        size_t reerroffset;

        backend->pattern_re =
            pcre2_compile((const uint8_t *)backend->pattern, PCRE2_ZERO_TERMINATED, 0, &reerr, &reerroffset, NULL);
        if (backend->pattern_re == NULL) {
            err("Regex compilation of \"%s\" failed: %d, offset %zu",
                    backend->pattern, reerr, reerroffset);
            return 0;
        }

        backend->pattern_match_data =
            pcre2_match_data_create_from_pattern(backend->pattern_re, NULL);
        if (backend->pattern_match_data == NULL) {
            err("Failed to allocate regex match data for pattern \"%s\"",
                    backend->pattern);
            pcre2_code_free(backend->pattern_re);
            backend->pattern_re = NULL;
            return 0;
        }

        char address[ADDRESS_BUFFER_SIZE];
        debug("Parsed %s %s",
                backend->pattern,
                display_address(backend->address,
                    address, sizeof(address)));
    }

    return 1;
}

int
valid_backend(const struct Backend *backend) {
    if (backend == NULL) {
        err("Invalid backend definition");
        return 0;
    }

    if (backend->pattern == NULL) {
        err("Backend is missing a match pattern");
        return 0;
    }

    if (backend->address == NULL) {
        err("Backend \"%s\" is missing a destination address", backend->pattern);
        return 0;
    }

    return 1;
}

struct Backend *
lookup_backend(const struct Backend_head *head, const char *name, size_t name_len) {
    struct Backend *iter;

    backend_regex_runtime_init();

    if (name == NULL) {
        name = "";
        name_len = 0;
    }

    uint32_t match_limit = backend_regex_match_limit_for_len(name_len);

    for (iter = STAILQ_FIRST(head); iter != NULL; iter = STAILQ_NEXT(iter, entries)) {
        if (iter->pattern_re == NULL)
            continue;

        int cached_result;
        if (backend_cached_result(iter, name, name_len, &cached_result)) {
            if (cached_result)
                return iter;
            continue;
        }
        pcre2_match_data *md = iter->pattern_match_data;
        if (md == NULL)
            continue;

        pcre2_set_match_limit(backend_match_ctx, match_limit);
        int ret = pcre2_match(iter->pattern_re, (const uint8_t *)name, name_len, 0, 0, md, backend_match_ctx);
        backend_store_match_cache(iter, name, name_len, ret >= 0);
        if (ret >= 0)
            return iter;
    }

    return NULL;
}

void
print_backend_config(FILE *file, const struct Backend *backend) {
    assert(backend != NULL);

    char address[ADDRESS_BUFFER_SIZE];

    fprintf(file, "\t%s %s%s\n",
            backend->pattern,
            display_address(backend->address, address, sizeof(address)),
            backend_config_options(backend));
}

static const char *
backend_config_options(const struct Backend *backend) {
    assert(backend != NULL);

    if (backend->use_proxy_header)
        return " proxy_protocol";
    else
        return "";
}

void
remove_backend(struct Backend_head *head, struct Backend *backend) {
    STAILQ_REMOVE(head, backend, Backend, entries);
    free_backend(backend);
}

void
free_backend(struct Backend *backend) {
    if (backend == NULL)
        return;

    free(backend->pattern);
    free(backend->address);
    free(backend->last_lookup_name);
    if (backend->pattern_match_data != NULL)
        pcre2_match_data_free(backend->pattern_match_data);
    if (backend->pattern_re != NULL)
        pcre2_code_free(backend->pattern_re);
    free(backend);
}

static void
backend_regex_cleanup(void) {
    if (backend_match_ctx != NULL) {
        pcre2_match_context_free(backend_match_ctx);
        backend_match_ctx = NULL;
    }
}

static void
backend_regex_runtime_init(void) {
    if (backend_match_ctx != NULL || backend_match_ctx_registered == -1)
        return;

    backend_match_ctx = pcre2_match_context_create(NULL);
    if (backend_match_ctx == NULL) {
        err("Failed to allocate PCRE2 match context for backend lookups");
        backend_match_ctx_registered = -1;
        return;
    }

    pcre2_set_match_limit(backend_match_ctx, BACKEND_REGEX_MATCH_LIMIT);
    pcre2_set_depth_limit(backend_match_ctx, BACKEND_REGEX_DEPTH_LIMIT);

    if (!backend_match_ctx_registered) {
        atexit(backend_regex_cleanup);
        backend_match_ctx_registered = 1;
    }
}
