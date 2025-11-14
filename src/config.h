/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#define DEFAULT_CLIENT_BUFFER_LIMIT (1U << 20)
#define DEFAULT_SERVER_BUFFER_LIMIT (1U << 20)
#define DEFAULT_MAX_CONNECTIONS 10000
#define MIN_CONNECTION_BUFFER_LIMIT (8U * 1024)
#define MAX_CONNECTION_BUFFER_LIMIT (1024U * 1024 * 1024U)

#define DEFAULT_CLIENT_BUFFER_LIMIT (1U << 20)
#define DEFAULT_SERVER_BUFFER_LIMIT (1U << 20)

#include <stdio.h>
#include "table.h"
#include "listener.h"
#include "resolv.h"

struct Config {
    char *filename;
    char *user;
    char *group;
    char *pidfile;
    struct ResolverConfig {
        char **nameservers;
        char **search;
        int mode;
        size_t max_concurrent_queries;
        int dnssec_validation_mode;
    } resolver;
    struct Logger *access_log;
    double per_ip_connection_rate;
    size_t max_connections;
    double io_collect_interval;
    double timeout_collect_interval;
    size_t client_buffer_limit;
    size_t server_buffer_limit;
    struct Listener_head listeners;
    struct Table_head tables;
};

struct Config *init_config(const char *, struct ev_loop *);
void reload_config(struct Config *, struct ev_loop *);
void free_config(struct Config *, struct ev_loop *);
void print_config(FILE *, struct Config *);

#endif
