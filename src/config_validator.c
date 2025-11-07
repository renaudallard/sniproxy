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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ev.h>

#include "config.h"
#include "logger.h"

#define PROGRAM_NAME "sniproxy-cfg"
#define DEFAULT_CONFIG_PATH "/etc/sniproxy.conf"

static void usage(const char *progname);

static void
usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-c <config>] [-p] [-h]\n", progname);
    fprintf(stderr, "       -c  configuration file to validate (defaults to %s)\n",
            DEFAULT_CONFIG_PATH);
    fprintf(stderr, "       -p  print normalized configuration to stdout\n");
    fprintf(stderr, "       -h  show this help message\n");
}

int
main(int argc, char **argv) {
    const char *config_file = DEFAULT_CONFIG_PATH;
    int print_config_flag = 0;
    int opt;

    while ((opt = getopt(argc, argv, "c:ph")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'p':
                print_config_flag = 1;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
    if (loop == NULL) {
        fprintf(stderr, "%s: failed to initialize event loop\n", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    struct Config *config = init_config(config_file, loop);
    if (config == NULL) {
        ev_loop_destroy(loop);
        return EXIT_FAILURE;
    }

    if (print_config_flag)
        print_config(stdout, config);

    printf("%s: configuration is valid\n", config_file);

    free_config(config, loop);
    ev_loop_destroy(loop);

    return EXIT_SUCCESS;
}
