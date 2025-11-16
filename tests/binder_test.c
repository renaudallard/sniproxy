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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "binder.h"

static int test_binder(int);

int main(void) {
    int i;

    if (geteuid() != 0) {
        fprintf(stderr, "binder_test requires root privileges; skipping\n");
        return 77;
    }

    start_binder();
    for (i = 8080; i <= 8084; i++)
        test_binder(i);

    stop_binder();

    return 0;
}

static int
test_binder(int port) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };

    int fd = bind_socket((struct sockaddr *)&addr, sizeof(addr));

    assert(fd >= 0);

    /* Verify we obtained the expected socket address */
    struct sockaddr_storage addr_verify;
    socklen_t len = sizeof(addr_verify);
    if (getsockname(fd, (struct sockaddr *)&addr_verify, &len) < 0) {
        perror("getsockname:");
        exit(1);
    }

    assert(addr.sin_family == ((struct sockaddr_in *)&addr_verify)->sin_family);
    assert(addr.sin_addr.s_addr == ((struct sockaddr_in *)&addr_verify)->sin_addr.s_addr);
    assert(addr.sin_port == ((struct sockaddr_in *)&addr_verify)->sin_port);

    /* Verify we can listen to it */
    if (listen(fd, 5) < 0) {
        perror("listen:");
        exit(1);
    }

    /* Test error handling: */
    fd = bind_socket((struct sockaddr *)&addr, sizeof(addr));
    assert(fd == -1);

    return 0;
}
