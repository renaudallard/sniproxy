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

#ifndef FD_UTIL_H
#define FD_UTIL_H

#include <fcntl.h>
#include <unistd.h>

/*
 * musl libc (Alpine) provides closefrom() but does not declare it in
 * any header.  Provide our own declaration to avoid implicit-function-
 * declaration errors with -Werror.
 */
#if defined(HAVE_CLOSEFROM) && !defined(__GLIBC__) && \
    !defined(__OpenBSD__) && !defined(__FreeBSD__) && !defined(__NetBSD__)
void closefrom(int);
#endif

static inline int
set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1)
        return -1;

    if ((flags & FD_CLOEXEC) != FD_CLOEXEC)
        return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

    return 0;
#else
    (void)fd;
    return 0;
#endif
}

/*
 * Prepare a freshly forked helper process: move the IPC socket to fd 0,
 * close every other inherited descriptor except stdout and stderr, and
 * point stdout or stderr at /dev/null when the parent did not have them
 * open. Keeping fd 1 and 2 occupied means a stray fprintf(stderr) or the
 * crash handler write in a sandboxed child can never land on a socket
 * that reused those numbers, while the child's messages still reach the
 * parent's stderr in foreground mode. Returns the IPC descriptor, which
 * is always 0, or -1 on failure. Nothing here logs: the caller has not
 * detached the parent's logging state yet.
 */
static inline int
fd_child_setup(int fd)
{
    if (fd < 0)
        return -1;

    if (fd != 0) {
        if (dup2(fd, 0) < 0)
            return -1;
        close(fd);
    }

#ifdef HAVE_CLOSEFROM
    closefrom(3);
#else
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0)
        max_fd = 256;

    for (int current = (int)max_fd - 1; current >= 3; current--)
        close(current);
#endif

    for (int target = 1; target <= 2; target++) {
        if (fcntl(target, F_GETFD) != -1)
            continue;

        int devnull = open("/dev/null", O_RDWR);
        if (devnull < 0)
            continue;
        if (devnull != target) {
            (void)dup2(devnull, target);
            close(devnull);
        }
    }

    return 0;
}
#endif /* FD_UTIL_H */
