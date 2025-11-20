/*
 * Copyright (c) 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include "cfg_parser.h"
#include "cfg_tokenizer.h"
#include "logger.h"

#define MAX_PARSE_DEPTH 32

static int parse_config_depth(void *, FILE *, const struct Keyword *, const char *, int);
static const struct Keyword *find_keyword(const struct Keyword *, const char *);
static void cleanup_keyword_context(const struct Keyword *, void *, void *);


int
parse_config(void *context, FILE *cfg, const struct Keyword *grammar,
        const char *context_name) {
    return parse_config_depth(context, cfg, grammar, context_name, 0);
}

static int
parse_config_depth(void *context, FILE *cfg, const struct Keyword *grammar,
        const char *context_name, int depth) {
    char buffer[256];
    const struct Keyword *keyword = NULL;
    void *sub_context = NULL;
    int result;
    const char *active_context = (context_name && *context_name) ?
            context_name : "global";

    if (depth > MAX_PARSE_DEPTH) {
        err("Configuration nesting too deep");
        return -1;
    }

    for (;;) {
        switch (next_token(cfg, buffer, sizeof(buffer))) {
            case TOKEN_ERROR:
                err("%s: tokenizer error", __func__);
                cleanup_keyword_context(keyword, context, sub_context);
                return -1;
            case TOKEN_WORD:
                if (keyword && sub_context && keyword->parse_arg) {
                    result = keyword->parse_arg(sub_context, buffer);
                    if (result <= 0) {
                        /* Free sub_context if it was newly created and parse_arg failed */
                        cleanup_keyword_context(keyword, context, sub_context);
                        return result;
                    }

                } else {
                    const struct Keyword *next_keyword =
                            find_keyword(grammar, buffer);
                    if (next_keyword) {
                        keyword = next_keyword;
                        if (keyword->create) {
                            sub_context = keyword->create();
                            if (sub_context == NULL) {
                                err("failed to create subcontext");
                                return -1;
                            }
                        } else {
                            sub_context = context;
                        }

                        /* Special case for wildcard grammars i.e. tables */
                        if (keyword->keyword == NULL && keyword->parse_arg) {
                            result = keyword->parse_arg(sub_context, buffer);
                            if (result <= 0) {
                                /* Free sub_context if it was newly created and parse_arg failed */
                                cleanup_keyword_context(keyword, context, sub_context);
                                return result;
                            }
                        }

                        break;
                    }

                    err("%s: unknown keyword %s in %s context", __func__,
                            buffer, active_context);
                    cleanup_keyword_context(keyword, context, sub_context);
                    return -1;
                }
                break;
            case TOKEN_OBRACE:
                if (keyword && sub_context && keyword->block_grammar) {
                    const char *child_context =
                            (keyword->keyword && *keyword->keyword) ?
                            keyword->keyword : active_context;
                    result = parse_config_depth(sub_context, cfg,
                                          keyword->block_grammar,
                                          child_context,
                                          depth + 1);
                    if (result > 0 && keyword->finalize)
                        result = keyword->finalize(context, sub_context);

                    if (result <= 0) {
                        /* Free sub_context if it was newly created and not finalized */
                        cleanup_keyword_context(keyword, context, sub_context);
                        return result;
                    }

                    keyword = NULL;
                    sub_context = NULL;
                } else {
                    err("%s: block without context", __func__);
                    cleanup_keyword_context(keyword, context, sub_context);
                    return -1;
                }
                break;
            case TOKEN_EOL:
                if (keyword && sub_context && keyword->finalize) {
                    result = keyword->finalize(context, sub_context);
                    if (result <= 0)
                        return result;
                }

                keyword = NULL;
                sub_context = NULL;

                break;
            case TOKEN_CBRACE:
                if (keyword && sub_context && keyword->finalize) {
                    result = keyword->finalize(context, sub_context);
                    if (result <= 0)
                        return result;
                }
                return 1;
            case TOKEN_END:
                cleanup_keyword_context(keyword, context, sub_context);
                return 1;
        }
    }
}

static const struct Keyword *
find_keyword(const struct Keyword *grammar, const char *word) {
    if (word == NULL)
        return NULL;

    for (; grammar->keyword; grammar++)
        if (strcmp(grammar->keyword, word) == 0)
            return grammar;

    /* Special case for wildcard grammars i.e. tables */
    if (grammar->keyword == NULL && grammar->create)
        return grammar;

    return NULL;
}

static void
cleanup_keyword_context(const struct Keyword *keyword, void *context, void *sub_context) {
    if (keyword && keyword->create && sub_context && sub_context != context) {
        if (keyword->cleanup)
            keyword->cleanup(sub_context);
        else
            free(sub_context);
    }
}
