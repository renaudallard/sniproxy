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
#include <arpa/inet.h>
#include <ev.h>
#include <assert.h>
#include "resolv.h"
#include "address.h"

static int query_count = 0;


static void query_cb(struct Address *result, void *data) {
    (void)data; /* unused */
    char ip_buf[INET6_ADDRSTRLEN];

    if (result != NULL &&
            address_is_sockaddr(result) &&
            display_address(result, ip_buf, sizeof(ip_buf))) {

        fprintf(stderr, "query resolved to %s\n", ip_buf);

        query_count++;
    }
}

static void
test_init_cb(struct ev_loop *loop __attribute__((unused)), struct ev_timer *w __attribute__((unused)), int revents) {
    if (revents & EV_TIMER)
        resolv_query("localhost", RESOLV_MODE_DEFAULT, query_cb, NULL, &query_count);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *w __attribute__((unused)), int revents) {
    if (revents & EV_TIMER)
        ev_break(loop, EVBREAK_ALL);
}


int main(void) {
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_timer timeout_watcher;
    struct ev_timer init_watcher;

    resolv_init(loop, NULL, NULL, 0, DNSSEC_VALIDATION_OFF);

    ev_timer_init(&init_watcher, &test_init_cb, 0.0, 0.0);
    ev_timer_start(loop, &init_watcher);
    ev_timer_init(&timeout_watcher, &timeout_cb, 5.0, 0.0);
    ev_timer_start(loop, &timeout_watcher);

    ev_run(loop, 0);

    resolv_shutdown(loop);

    return 0;
}
