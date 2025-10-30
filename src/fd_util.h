#ifndef FD_UTIL_H
#define FD_UTIL_H

#include <fcntl.h>

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

#endif /* FD_UTIL_H */
