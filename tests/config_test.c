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

static char *
generate_test_config(void) {
    char template[] = "/tmp/sniproxy-config-testXXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return NULL;

    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template);
        return NULL;
    }

    char log_template[] = "/tmp/sniproxy-config-logXXXXXX";
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

    return 0;
}
