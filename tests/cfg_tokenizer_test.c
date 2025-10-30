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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cfg_tokenizer.h"


struct Result {
    enum Token type;
    const char *value;
};

struct Test {
    const char *config;
    struct Result *results;
    int len;
};

static char config1[] = "# Comment\n"
                 "numbers {\n"
                 "   one\n"
                 "   two\n"
                 "   three\n"
                 "   \"[0-9a-z-]+\\.edu\"\n"
                 "}";
static struct Result results1[] = {
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "numbers" },
    { TOKEN_OBRACE, NULL },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "one" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "two" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "three" },
    { TOKEN_EOL, NULL },
    { TOKEN_WORD, "[0-9a-z-]+.edu" },
    { TOKEN_EOL, NULL },
    { TOKEN_CBRACE, NULL },
    { TOKEN_END, NULL },
};

static struct Test tests[] = {
    { config1, results1, sizeof(results1) / sizeof(struct Result) },
    { NULL, NULL, 0 } /* End of tests */
};

int main(void) {
    FILE *cfg;
    char buffer[256];
    enum Token token;
    struct Test *test;
    int i;

    cfg = tmpfile();
    if (cfg == NULL) {
        perror("tmpfile");
        return 1;
    }

    for (test = tests; test->config; test++) {
        fprintf(cfg, "%s", test->config);
        rewind(cfg);

        for (i = 0; i < test->len; i++) {
            token = next_token(cfg, buffer, sizeof(buffer));
            assert(token == test->results[i].type);
            if (test->results[i].value)
                assert(strncmp(buffer, test->results[i].value, sizeof(buffer)) == 0);
        }
        rewind(cfg);
    }

    fclose(cfg);
    return (0);
}
