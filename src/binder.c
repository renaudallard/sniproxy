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
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <signal.h>
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#ifdef HAVE_BSD_UNISTD_H
#include <bsd/unistd.h>
#endif
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
static int binder_validate_sockaddr(const struct sockaddr *addr, size_t addr_len);
static int binder_sockaddr_equal(const struct sockaddr *a, size_t alen,
        const struct sockaddr *b, size_t blen);
static int binder_sync_allowlist_to_child(void);
static int binder_send_register(const struct sockaddr *addr, size_t addr_len);


struct binder_request {
    uint8_t cmd;
    uint8_t reserved[7];
    size_t address_len;
    struct sockaddr address[];
};


#define BINDER_CMD_BIND     1
#define BINDER_CMD_REGISTER 2

#define BINDER_IPC_MAX_PAYLOAD 512
#define BINDER_IPC_CHANNEL_ID 0x424e4452u /* BNDR */

static int binder_sock = -1; /* socket to binder */
static pid_t binder_pid = -1;
static struct ipc_crypto_state binder_crypto_parent;
static struct ipc_crypto_state binder_crypto_child;

struct binder_allowed_addr {
    struct sockaddr_storage addr;
    socklen_t len;
};

static struct binder_allowed_addr *allowed_addrs;
static size_t allowed_count;
static size_t allowed_capacity;
static struct binder_allowed_addr *parent_allowed;
static size_t parent_allowed_count;
static size_t parent_allowed_capacity;

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
binder_send_register(const struct sockaddr *addr, size_t addr_len) {
    if (addr_len > BINDER_IPC_MAX_PAYLOAD - sizeof(struct binder_request))
        return -1;

    if (!binder_validate_sockaddr(addr, addr_len))
        return -1;

    uint8_t buffer[sizeof(struct binder_request) + BINDER_IPC_MAX_PAYLOAD];
    struct binder_request *req = (struct binder_request *)buffer;
    memset(req, 0, sizeof(*req));
    req->cmd = BINDER_CMD_REGISTER;
    req->address_len = addr_len;
    memcpy(&req->address, addr, addr_len);

    if (binder_pid <= 0 || binder_sock < 0)
        return -1;

    if (ipc_crypto_send_msg(&binder_crypto_parent, binder_sock,
            buffer, sizeof(*req) + addr_len, -1) < 0) {
        return -1;
    }

    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int rc = ipc_crypto_recv_msg(&binder_crypto_parent, binder_sock,
            BINDER_IPC_MAX_PAYLOAD, &reply, &reply_len, NULL);
    if (rc <= 0) {
        free(reply);
        return -1;
    }

    int status = -1;
    if (reply_len == 1 && reply[0] == 0)
        status = 0;

    free(reply);
    return status;
}

int
binder_register_allowed_address(const struct sockaddr *addr, size_t addr_len) {
    if (addr == NULL || addr_len == 0)
        return -1;

    if (!binder_validate_sockaddr(addr, addr_len))
        return -1;

    /* Check for duplicate registration */
    for (size_t i = 0; i < parent_allowed_count; i++) {
        if (binder_sockaddr_equal(addr, addr_len,
                    (struct sockaddr *)&parent_allowed[i].addr,
                    parent_allowed[i].len)) {
            return 0; /* Already registered, success */
        }
    }

    if (parent_allowed_count == parent_allowed_capacity) {
        size_t new_cap = parent_allowed_capacity == 0 ? 8 : parent_allowed_capacity * 2;
        if (new_cap < parent_allowed_capacity ||
                new_cap > SIZE_MAX / sizeof(*parent_allowed))
            return -1;
        struct binder_allowed_addr *tmp = realloc(parent_allowed,
                new_cap * sizeof(*tmp));
        if (tmp == NULL)
            return -1;
        parent_allowed = tmp;
        parent_allowed_capacity = new_cap;
    }

    struct binder_allowed_addr *slot = &parent_allowed[parent_allowed_count];
    memset(slot, 0, sizeof(*slot));
    slot->len = (socklen_t)addr_len;
    memcpy(&slot->addr, addr, addr_len);
    parent_allowed_count++;

    return binder_send_register(addr, addr_len);
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
        if (child_fd < 0) {
            err("binder child: failed to preserve IPC socket: %s", strerror(errno));
            binder_child_exit(EXIT_FAILURE);
        }

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
binder_sync_allowlist_to_child(void) {
    if (binder_pid <= 0 || binder_sock < 0)
        return -1;

    for (size_t i = 0; i < parent_allowed_count; i++) {
        const struct binder_allowed_addr *entry = &parent_allowed[i];
        if (binder_send_register((struct sockaddr *)&entry->addr,
                    (size_t)entry->len) < 0) {
            return -1;
        }
    }

    return 0;
}

static int
binder_restart_child(void) {
    binder_cleanup_child(0);

    if (binder_pid > 0) {
        kill(binder_pid, SIGTERM);
        binder_cleanup_child(1);
    }

    if (binder_spawn_child() < 0)
        return -1;

    return binder_sync_allowlist_to_child();
}

int
bind_socket(const struct sockaddr *addr, size_t addr_len) {
    if (addr_len > BINDER_IPC_MAX_PAYLOAD - sizeof(struct binder_request))
        fatal("bind_socket: address length %zu exceeds buffer", addr_len);

    size_t request_len = sizeof(struct binder_request) + addr_len;
    uint8_t buffer[sizeof(struct binder_request) + BINDER_IPC_MAX_PAYLOAD];
    struct binder_request *request = (struct binder_request *)buffer;
    memset(request, 0, sizeof(*request));
    request->cmd = BINDER_CMD_BIND;
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
    free(parent_allowed);
    parent_allowed = NULL;
    parent_allowed_count = 0;
    parent_allowed_capacity = 0;
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
        err("binder: pledge failed: %s", strerror(errno));
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

        if (req->cmd != BINDER_CMD_BIND && req->cmd != BINDER_CMD_REGISTER) {
            const char *msg = "Unknown binder command";
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    msg, strlen(msg), -1);
            free(plain);
            continue;
        }

        if (!binder_validate_sockaddr(req->address, req->address_len)) {
            const char *msg = "Address family or format not permitted";
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    msg, strlen(msg), -1);
            free(plain);
            continue;
        }

        if (req->cmd == BINDER_CMD_REGISTER) {
            /* Check for duplicate registration */
            int already_registered = 0;
            for (size_t i = 0; i < allowed_count; i++) {
                if (binder_sockaddr_equal(req->address, req->address_len,
                            (struct sockaddr *)&allowed_addrs[i].addr,
                            allowed_addrs[i].len)) {
                    already_registered = 1;
                    break;
                }
            }
            if (already_registered) {
                uint8_t status = 0;
                ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                        &status, sizeof(status), -1);
                free(plain);
                continue;
            }

            if (allowed_count == allowed_capacity) {
                size_t new_cap = allowed_capacity == 0 ? 8 : allowed_capacity * 2;
                if (new_cap < allowed_capacity ||
                        new_cap > SIZE_MAX / sizeof(*allowed_addrs)) {
                    const char *msg = "Allowlist capacity overflow";
                    ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                            msg, strlen(msg), -1);
                    free(plain);
                    continue;
                }
                struct binder_allowed_addr *tmp = realloc(allowed_addrs,
                        new_cap * sizeof(*tmp));
                if (tmp == NULL) {
                    const char *msg = "Unable to grow allowlist";
                    ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                            msg, strlen(msg), -1);
                    free(plain);
                    continue;
                }
                allowed_addrs = tmp;
                allowed_capacity = new_cap;
            }

            struct binder_allowed_addr *slot = &allowed_addrs[allowed_count];
            memset(slot, 0, sizeof(*slot));
            slot->len = (socklen_t)req->address_len;
            memcpy(&slot->addr, req->address, req->address_len);
            allowed_count++;

            uint8_t status = 0;
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    &status, sizeof(status), -1);
            free(plain);
            continue;
        }

        if (allowed_count == 0) {
            const char *msg = "Binder allowlist empty; cannot bind";
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    msg, strlen(msg), -1);
            free(plain);
            continue;
        }

        int found = 0;
        for (size_t i = 0; i < allowed_count; i++) {
            if (binder_sockaddr_equal(req->address, req->address_len,
                        (struct sockaddr *)&allowed_addrs[i].addr,
                        allowed_addrs[i].len)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            const char *msg = "Requested bind address not in allowlist";
            ipc_crypto_send_msg(&binder_crypto_child, sockfd,
                    msg, strlen(msg), -1);
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

static int
binder_validate_sockaddr(const struct sockaddr *addr, size_t addr_len) {
    if (addr == NULL || addr_len < sizeof(sa_family_t))
        return 0;

    switch (addr->sa_family) {
        case AF_INET:
            return addr_len >= sizeof(struct sockaddr_in);
        case AF_INET6:
            return addr_len >= sizeof(struct sockaddr_in6);
        case AF_UNIX: {
            if (addr_len < offsetof(struct sockaddr_un, sun_path) + 2)
                return 0;
            const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
            size_t max_len = addr_len - offsetof(struct sockaddr_un, sun_path);
            size_t path_len = strnlen(sun->sun_path, max_len);
            if (path_len == 0 || path_len >= max_len)
                return 0;
            /* Reject abstract sockets and relative paths. */
            if (sun->sun_path[0] != '/')
                return 0;
            return 1;
        }
        default:
            return 0;
    }
}

static int
binder_sockaddr_equal(const struct sockaddr *a, size_t alen,
        const struct sockaddr *b, size_t blen) {
    if (a == NULL || b == NULL || a->sa_family != b->sa_family)
        return 0;

    switch (a->sa_family) {
        case AF_INET: {
            if (alen < sizeof(struct sockaddr_in) || blen < sizeof(struct sockaddr_in))
                return 0;
            const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
            const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
            return a4->sin_port == b4->sin_port &&
                memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr)) == 0;
        }
        case AF_INET6: {
            if (alen < sizeof(struct sockaddr_in6) || blen < sizeof(struct sockaddr_in6))
                return 0;
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
            return a6->sin6_port == b6->sin6_port &&
                a6->sin6_flowinfo == b6->sin6_flowinfo &&
                a6->sin6_scope_id == b6->sin6_scope_id &&
                memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
        }
        case AF_UNIX: {
            const struct sockaddr_un *au = (const struct sockaddr_un *)a;
            const struct sockaddr_un *bu = (const struct sockaddr_un *)b;
            size_t a_max = alen - offsetof(struct sockaddr_un, sun_path);
            size_t b_max = blen - offsetof(struct sockaddr_un, sun_path);
            size_t a_len = strnlen(au->sun_path, a_max);
            size_t b_len = strnlen(bu->sun_path, b_max);
            if (a_len == 0 || b_len == 0 || a_len >= a_max || b_len >= b_max)
                return 0;
            return a_len == b_len && memcmp(au->sun_path, bu->sun_path, a_len) == 0;
        }
        default:
            return 0;
    }
}
