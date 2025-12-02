/*
 * Copyright (c) 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include <string.h> /* memcpy() */
#include <errno.h> /* errno */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <signal.h>
#include "binder.h"
#include "logger.h"
#include "fd_util.h"
#include "ipc_crypto.h"
#include "seccomp_filter.h"

/*
 * binder is a child process we spawn before dropping privileges that is
 * responsible for creating new bound sockets to low ports
 */

static void binder_main(int);
static int binder_spawn_child(void);
static int binder_restart_child(void);
static void binder_cleanup_child(int block);


struct binder_request {
    size_t address_len;
    struct sockaddr address[];
};


#define BINDER_IPC_MAX_PAYLOAD 512
#define BINDER_IPC_CHANNEL_ID 0x424e4452u /* BNDR */

static int binder_sock = -1; /* socket to binder */
static pid_t binder_pid = -1;
static struct ipc_crypto_state binder_crypto_parent;
static struct ipc_crypto_state binder_crypto_child;

static void __attribute__((noreturn))
binder_child_exit(int status) {
    ipc_crypto_state_clear(&binder_crypto_child);
    _exit(status);
}

void
start_binder(void) {
    if (binder_spawn_child() < 0)
        err("failed to start binder helper");
}

static int
binder_spawn_child(void) {
    int sockets[2];
    int socket_type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif

    if (socketpair(AF_UNIX, socket_type, 0, sockets) < 0) {
        err("sockpair: %s", strerror(errno));
        return -1;
    }

    if (set_cloexec(sockets[0]) < 0 || set_cloexec(sockets[1]) < 0) {
        err("failed to set close-on-exec on binder socket: %s", strerror(errno));
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) { /* error case */
        err("fork: %s", strerror(errno));
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    } else if (pid == 0) { /* child */
        close(sockets[0]);
        int child_fd = fd_preserve_only(sockets[1]);
        if (child_fd < 0)
            binder_child_exit(EXIT_FAILURE);

        binder_main(child_fd);
        binder_child_exit(EXIT_SUCCESS);
    }

    close(sockets[1]);
    binder_sock = sockets[0];
    ipc_crypto_channel_init(&binder_crypto_parent, BINDER_IPC_CHANNEL_ID,
            IPC_CRYPTO_ROLE_PARENT);
    binder_pid = pid;

    return 0;
}

static void
binder_cleanup_child(int block) {
    if (binder_sock >= 0) {
        close(binder_sock);
        binder_sock = -1;
    }

    if (binder_pid > 0) {
        int status;
        int options = block ? 0 : WNOHANG;
        pid_t result;
        do {
            result = waitpid(binder_pid, &status, options);
        } while (result < 0 && errno == EINTR);

        if (result > 0 || (result == 0 && block) || (result < 0 && errno == ECHILD))
            binder_pid = -1;
    }

    if (binder_pid <= 0)
        ipc_crypto_state_clear(&binder_crypto_parent);
}

static int
binder_restart_child(void) {
    binder_cleanup_child(0);

    if (binder_pid > 0) {
        kill(binder_pid, SIGTERM);
        binder_cleanup_child(1);
    }

    return binder_spawn_child();
}

int
bind_socket(const struct sockaddr *addr, size_t addr_len) {
    if (addr_len > BINDER_IPC_MAX_PAYLOAD - sizeof(struct binder_request))
        fatal("bind_socket: address length %zu exceeds buffer", addr_len);

    size_t request_len = sizeof(struct binder_request) + addr_len;
    uint8_t buffer[sizeof(struct binder_request) + BINDER_IPC_MAX_PAYLOAD];
    struct binder_request *request = (struct binder_request *)buffer;
    request->address_len = addr_len;
    memcpy(&request->address, addr, addr_len);

    for (int attempt = 0; attempt < 2; attempt++) {
        if (binder_pid <= 0 || binder_sock < 0) {
            if (binder_restart_child() < 0) {
                err("%s: Binder not started", __func__);
                return -1;
            }
        }

        if (ipc_crypto_send_msg(&binder_crypto_parent, binder_sock,
                buffer, request_len, -1) < 0) {
            if ((errno == EPIPE || errno == ECONNRESET) &&
                    binder_restart_child() == 0)
                continue;
            err("binder request send failed: %s", strerror(errno));
            return -1;
        }

        uint8_t *reply = NULL;
        size_t reply_len = 0;
        int received_fd = -1;
        int rc = ipc_crypto_recv_msg(&binder_crypto_parent, binder_sock,
                BINDER_IPC_MAX_PAYLOAD, &reply, &reply_len, &received_fd);
        if (rc <= 0) {
            free(reply);
            if ((errno == EPIPE || errno == ECONNRESET) &&
                    binder_restart_child() == 0)
                continue;
            err("binder response recv failed: %s", strerror(errno));
            return -1;
        }

        if (received_fd >= 0) {
            free(reply);
            if (set_cloexec(received_fd) < 0) {
                err("failed to set close-on-exec on bound socket: %s",
                        strerror(errno));
                close(received_fd);
                return -1;
            }
            return received_fd;
        }

        if (reply_len > 0)
            err("binder returned: %.*s", (int)reply_len, (char *)reply);
        else
            err("binder returned unknown error");
        free(reply);
        return -1;
    }

    return -1;
}


void
stop_binder(void) {
    binder_cleanup_child(1);
}

static void
binder_main(int sockfd) {
#ifdef __linux__
    (void)prctl(PR_SET_NAME, "sniproxy-binder", 0, 0, 0);
#endif
#ifdef HAVE_SETPROCTITLE
    setproctitle("sniproxy-binder");
#endif

#ifdef __OpenBSD__
    if (pledge("stdio unix inet", NULL) == -1) {
        perror("binder pledge");
        binder_child_exit(EXIT_FAILURE);
    }
#endif

    if (ipc_crypto_channel_init(&binder_crypto_child, BINDER_IPC_CHANNEL_ID,
            IPC_CRYPTO_ROLE_CHILD) < 0) {
        err("binder child: failed to initialize crypto context");
        binder_child_exit(EXIT_FAILURE);
    }

    /* Install seccomp filter after initialization */
    if (seccomp_available()) {
        if (seccomp_install_filter(SECCOMP_PROCESS_BINDER) < 0) {
            fatal("binder: failed to install seccomp filter: %s", strerror(errno));
        }
    }

    for (;;) {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        int rc = ipc_crypto_recv_msg(&binder_crypto_child, sockfd,
                BINDER_IPC_MAX_PAYLOAD, &plain, &plain_len, NULL);
        if (rc == 0) {
            close(sockfd);
            break;
        } else if (rc < 0) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "recv(): %s", strerror(errno));
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strnlen(errbuf, sizeof(errbuf)), -1);
            continue;
        }

        if (plain_len < sizeof(struct binder_request)) {
            const char *msg = "Incomplete request";
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    msg, strlen(msg), -1);
            free(plain);
            continue;
        }

        struct binder_request *req = (struct binder_request *)plain;
        size_t header_size = sizeof(*req);
        if (req->address_len == 0 ||
                req->address_len > plain_len - header_size) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf),
                    "Invalid address length: %zu", req->address_len);
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strlen(errbuf), -1);
            free(plain);
            continue;
        }

        int socket_type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
        socket_type |= SOCK_CLOEXEC;
#endif
        int fd = socket(req->address[0].sa_family, socket_type, 0);
        if (fd < 0) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "socket(): %s", strerror(errno));
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strlen(errbuf), -1);
            free(plain);
            continue;
        }

        if (set_cloexec(fd) < 0) {
            int saved_errno = errno;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "fcntl(FD_CLOEXEC): %s",
                    strerror(saved_errno));
            close(fd);
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strlen(errbuf), -1);
            free(plain);
            continue;
        }

        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf),
                    "setsockopt SO_REUSEADDR failed: %s", strerror(errno));
            close(fd);
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strlen(errbuf), -1);
            free(plain);
            continue;
        }

        if (bind(fd, req->address, req->address_len) < 0) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "bind(): %s", strerror(errno));
            close(fd);
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    errbuf, strlen(errbuf), -1);
            free(plain);
            continue;
        }

        uint8_t status = 0;
        if (ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                &status, sizeof(status), fd) < 0) {
            err("binder child: failed to send bound socket");
        }
        close(fd);
        free(plain);
    }
}
