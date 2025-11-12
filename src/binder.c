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

/*
 * binder is a child process we spawn before dropping privileges that is
 * responsible for creating new bound sockets to low ports
 */

static void binder_main(int);
static int parse_ancillary_data(struct msghdr *);
static int binder_spawn_child(void);
static int binder_restart_child(void);
static void binder_cleanup_child(int block);
static ssize_t recv_full(int, void *, size_t);


struct binder_request {
    size_t address_len;
    struct sockaddr address[];
};


static int binder_sock = -1; /* socket to binder */
static pid_t binder_pid = -1;


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
        /* don't leak file descriptors to the child process */
        for (int i = 0; i < sockets[1]; i++)
            close(i);

        binder_main(sockets[1]);
        exit(0);
    }

    close(sockets[1]);
    binder_sock = sockets[0];
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
}

static int
binder_restart_child(void) {
    binder_cleanup_child(0);

    if (binder_pid > 0) {
        kill(binder_pid, SIGTERM);
        binder_cleanup_child(1);
    }

    if (geteuid() != 0) {
        err("cannot restart binder after privilege drop");
        return -1;
    }

    return binder_spawn_child();
}

int
bind_socket(const struct sockaddr *addr, size_t addr_len) {
    struct binder_request *request;
    struct msghdr msg;
    struct iovec iov[1];
    char control_buf[64];
    char data_buf[256];


    if (addr_len > sizeof(data_buf) - sizeof(struct binder_request))
        fatal("bind_socket: address length %zu exceeds buffer", addr_len);

    size_t request_len = sizeof(struct binder_request) + addr_len;
    if (request_len > sizeof(data_buf))
        fatal("bind_socket: request length %zu exceeds buffer", request_len);
    request = (struct binder_request *)data_buf;
    request->address_len = addr_len;
    memcpy(&request->address, addr, addr_len);

    for (int attempt = 0; attempt < 2; attempt++) {
        if (binder_pid <= 0 || binder_sock < 0) {
            if (binder_restart_child() < 0) {
                err("%s: Binder not started", __func__);
                return -1;
            }
        }

        if (send(binder_sock, request, request_len, 0) < 0) {
            if ((errno == EPIPE || errno == ECONNRESET) &&
                    binder_restart_child() == 0)
                continue;
            err("send: %s", strerror(errno));
            return -1;
        }

        memset(&msg, 0, sizeof(msg));
        iov[0].iov_base = data_buf;
        iov[0].iov_len = sizeof(data_buf);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_buf;
        msg.msg_controllen = sizeof(control_buf);

        int len = recvmsg(binder_sock, &msg, 0);
        if (len < 0) {
            if ((errno == EPIPE || errno == ECONNRESET) &&
                    binder_restart_child() == 0)
                continue;
            err("recvmsg: %s", strerror(errno));
            return -1;
        } else if (len == 0) {
            if (binder_restart_child() == 0)
                continue;
            err("binder socket closed unexpectedly");
            return -1;
        }

        int fd = parse_ancillary_data(&msg);
        if (fd >= 0 && set_cloexec(fd) < 0) {
            err("failed to set close-on-exec on bound socket: %s", strerror(errno));
            close(fd);
            return -1;
        }
        if (fd < 0) {
            err("binder returned: %.*s", len, data_buf);
            return -1;
        }

        return fd;
    }

    return -1;
}

void
stop_binder(void) {
    binder_cleanup_child(1);
}


static ssize_t
recv_full(int fd, void *buf, size_t len) {
    size_t received = 0;
    char *ptr = (char *)buf;

    while (received < len) {
        ssize_t ret = recv(fd, ptr + received, len - received, 0);
        if (ret == 0) {
            if (received == 0)
                return 0;
            errno = ECONNRESET;
            return -1;
        }
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        received += (size_t)ret;
    }

    return (ssize_t)received;
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
        _exit(EXIT_FAILURE);
    }
#endif

    for (;;) {
        char buffer[256];
        size_t header_size = sizeof(struct binder_request);
        ssize_t len = recv_full(sockfd, buffer, header_size);
        if (len == 0) {
            close(sockfd);
            break;
        } else if (len < 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "recv(): %s", strerror(errno));
            goto error;
        }

        struct binder_request *req = (struct binder_request *)buffer;

        if (req->address_len == 0 ||
                req->address_len > sizeof(buffer) - header_size) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer),
                    "Invalid address length: %zu", req->address_len);
            goto error;
        }

        if (recv_full(sockfd, buffer + header_size, req->address_len) <= 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "recv(): %s", strerror(errno));
            goto error;
        }

        int socket_type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
        socket_type |= SOCK_CLOEXEC;
#endif
        int fd = socket(req->address[0].sa_family, socket_type, 0);
        if (fd < 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "socket(): %s", strerror(errno));
            goto error;
        }

        if (set_cloexec(fd) < 0) {
            int saved_errno = errno;
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "fcntl(FD_CLOEXEC): %s", strerror(saved_errno));
            close(fd);
            goto error;
        }

        /* set SO_REUSEADDR on server socket to facilitate restart */
        int on = 1;
        int result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (result < 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "setsockopt SO_REUSEADDR failed: %s", strerror(errno));
            goto error;
        }

        if (bind(fd, req->address, req->address_len) < 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "bind(): %s", strerror(errno));
            goto error;
        }

        struct msghdr msg;
        struct iovec iov[1];
        struct cmsghdr *cmsg;
        char control_data[64];
        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));
        memset(&control_data, 0, sizeof(control_data));
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_data;
        msg.msg_controllen = sizeof(control_data);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
        int *fdptr = (int *)CMSG_DATA(cmsg);
        memcpy(fdptr, &fd, sizeof(fd));
        msg.msg_controllen = cmsg->cmsg_len;

        if (sendmsg(sockfd, &msg, 0) < 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "send: %s", strerror(errno));
            goto error;
        }

        close(fd);

        continue;

        error:

        if (send(sockfd, buffer, strlen(buffer), 0) < 0) {
            err("send: %s", strerror(errno));
            close(sockfd);
            break;
        }
    }
}

static int
parse_ancillary_data(struct msghdr *m) {
    struct cmsghdr *cmsg;
    int fd = -1;
    int *fdptr;

    for (cmsg = CMSG_FIRSTHDR(m); cmsg != NULL; cmsg = CMSG_NXTHDR(m, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            fdptr = (int *)CMSG_DATA(cmsg);
            memcpy(&fd, fdptr, sizeof(fd));
        }
    }

    return fd;
}
