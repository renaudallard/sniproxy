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

static inline int
fd_preserve_only(int fd)
{
#ifdef HAVE_CLOSEFROM
    if (fd < 0) {
        closefrom(0);
        return -1;
    }

    if (fd != 0) {
        if (dup2(fd, 0) < 0)
            return -1;
        close(fd);
        fd = 0;
    }

    closefrom(1);
    return fd;
#else
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0)
        max_fd = 256;

    for (int current = (int)max_fd - 1; current >= 0; current--) {
        if (current == fd)
            continue;
        close(current);
    }

    return fd;
#endif
}
#endif /* FD_UTIL_H */
