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

#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include "config.h"

static char *generated_log_path;

/* Honor TMPDIR if the caller exported one; default to /tmp so that
 * `make check` works without extra setup.  Both files are unlinked in
 * cleanup_test_config(). */
static const char *
config_test_tmpdir(void) {
    const char *t = getenv("TMPDIR");
    return (t != NULL && t[0] == '/') ? t : "/tmp";
}

static char *
generate_test_config(void) {
    char template[256];
    if (snprintf(template, sizeof(template),
                "%s/sniproxy-config-testXXXXXX",
                config_test_tmpdir()) >= (int)sizeof(template))
        return NULL;
    int fd = mkstemp(template);
    if (fd < 0)
        return NULL;

    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template);
        return NULL;
    }

    char log_template[256];
    if (snprintf(log_template, sizeof(log_template),
                "%s/sniproxy-config-logXXXXXX",
                config_test_tmpdir()) >= (int)sizeof(log_template)) {
        fclose(fp);
        unlink(template);
        return NULL;
    }
    int log_fd = mkstemp(log_template);
    if (log_fd < 0) {
        fclose(fp);
        unlink(template);
        return NULL;
    }
    close(log_fd);
    free(generated_log_path);
    generated_log_path = strdup(log_template);

    struct passwd *pw = getpwuid(geteuid());
    struct group *gr = getgrgid(getegid());
    const char *user = pw != NULL ? pw->pw_name : "nobody";
    const char *group = gr != NULL ? gr->gr_name : "nogroup";

    fprintf(fp,
            "user %s\n"
            "group %s\n"
            "error_log { filename %s }\n"
            "access_log { filename %s }\n"
            "listen 127.0.0.1 8080 {\n"
            "    proto http\n"
            "}\n\n"
            "table {\n"
            "    localhost 127.0.0.1 8081\n"
            "}\n",
            user, group, log_template, log_template);

    fclose(fp);

    return strdup(template);
}

/* A directive on the last line of a file without a trailing newline
 * must not be silently dropped. */
static int
test_missing_trailing_newline(void) {
    char template[256];
    if (snprintf(template, sizeof(template),
                "%s/sniproxy-config-testXXXXXX",
                config_test_tmpdir()) >= (int)sizeof(template))
        return 1;
    int fd = mkstemp(template);
    if (fd < 0)
        return 1;

    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template);
        return 1;
    }

    fprintf(fp,
            "table {\n"
            "    localhost 127.0.0.1 8081\n"
            "}\n"
            "listen 127.0.0.1 8080 {\n"
            "    proto http\n"
            "}\n"
            "listen 127.0.0.1 8082");

    fclose(fp);

    struct Config *config = init_config(template, EV_DEFAULT, 1);
    unlink(template);
    if (config == NULL) {
        fprintf(stderr, "Failed to parse config without trailing newline\n");
        return 1;
    }

    int listeners = 0;
    struct Listener *listener;
    SLIST_FOREACH(listener, &config->listeners, entries)
        listeners++;

    free_config(config, EV_DEFAULT);

    if (listeners != 2) {
        fprintf(stderr, "Expected 2 listeners, got %d: final directive "
                "without trailing newline was dropped\n", listeners);
        return 1;
    }

    return 0;
}

/* A listener referencing a table the config does not define must be
 * rejected at config load, not only by init_listener() at startup. */
static int
test_undefined_table_rejected(void) {
    char template[256];
    if (snprintf(template, sizeof(template),
                "%s/sniproxy-config-testXXXXXX",
                config_test_tmpdir()) >= (int)sizeof(template))
        return 1;
    int fd = mkstemp(template);
    if (fd < 0)
        return 1;

    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template);
        return 1;
    }

    fprintf(fp,
            "listen 127.0.0.1 8080 {\n"
            "    proto http\n"
            "    table missing\n"
            "}\n"
            "table hosts {\n"
            "    localhost 127.0.0.1 8081\n"
            "}\n");

    fclose(fp);

    struct Config *config = init_config(template, EV_DEFAULT, 1);
    unlink(template);
    if (config != NULL) {
        fprintf(stderr, "Config with undefined table reference was accepted\n");
        free_config(config, EV_DEFAULT);
        return 1;
    }

    return 0;
}

/* Duplicate table names make table_lookup() ambiguous and must be
 * rejected at config load. */
static int
test_duplicate_table_rejected(void) {
    char template[256];
    if (snprintf(template, sizeof(template),
                "%s/sniproxy-config-testXXXXXX",
                config_test_tmpdir()) >= (int)sizeof(template))
        return 1;
    int fd = mkstemp(template);
    if (fd < 0)
        return 1;

    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template);
        return 1;
    }

    fprintf(fp,
            "listen 127.0.0.1 8080 {\n"
            "    proto http\n"
            "    table hosts\n"
            "}\n"
            "table hosts {\n"
            "    localhost 127.0.0.1 8081\n"
            "}\n"
            "table hosts {\n"
            "    localhost 127.0.0.1 8082\n"
            "}\n");

    fclose(fp);

    struct Config *config = init_config(template, EV_DEFAULT, 1);
    unlink(template);
    if (config != NULL) {
        fprintf(stderr, "Config with duplicate table names was accepted\n");
        free_config(config, EV_DEFAULT);
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {
    const char *config_file = NULL;
    char *generated = NULL;
    struct Config *config;

    if (argc >= 2) {
        config_file = argv[1];
    } else {
        generated = generate_test_config();
        config_file = generated;
    }

    if (config_file == NULL) {
        fprintf(stderr, "Failed to write temporary config\n");
        return 1;
    }

    config = init_config(config_file, EV_DEFAULT, 1);
    if (config == NULL) {
        fprintf(stderr, "Failed to parse config\n");
        if (generated != NULL) {
            unlink(generated);
            free(generated);
        }
        return 1;
    }

    print_config(stdout, config);

    free_config(config, EV_DEFAULT);
    if (generated != NULL) {
        unlink(generated);
        free(generated);
    }
    if (generated_log_path != NULL) {
        unlink(generated_log_path);
        free(generated_log_path);
        generated_log_path = NULL;
    }

    if (test_missing_trailing_newline() != 0)
        return 1;

    if (test_duplicate_table_rejected() != 0)
        return 1;

    if (test_undefined_table_rejected() != 0)
        return 1;

    return 0;
}
