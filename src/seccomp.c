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

#include "seccomp_filter.h"

#if defined(__linux__) && defined(HAVE_SECCOMP)

#include <errno.h>
#include <seccomp.h>
#include <stddef.h>

static const char *const common_syscalls[] = {
    "read", "write", "readv", "writev", "pwrite64", "pread64",
    "pwritev", "preadv",
    "close", "lseek", "fstat", "fstat64",
    "brk", "madvise", "mmap", "mprotect", "mremap", "munmap",
    "clock_gettime", "clock_getres", "clock_nanosleep", "gettimeofday", "nanosleep", "time",
    "getpid", "getppid", "gettid", "getrusage",
    "getuid", "geteuid", "getgid", "getegid", "getgroups", "getcwd",
    "uname", "sysinfo",
    "futex", "set_robust_list", "set_tid_address",
    "sched_yield", "sched_getaffinity", "sched_getparam", "sched_setscheduler",
    "restart_syscall", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigaltstack", "tgkill", "rt_sigtimedwait",
    "prctl", "prlimit64", "getrlimit", "setrlimit",
    "getrandom",
    "umask",
    "exit", "exit_group",
    NULL,
};

static const char *const fs_read_syscalls[] = {
    "open", "openat", "openat2",
    "stat", "lstat", "newfstatat", "fstatfs", "statfs", "statx",
    "readlink", "readlinkat",
    "faccessat", "access",
    NULL,
};

static const char *const fs_write_syscalls[] = {
    "fchmod", "fchmodat", "chmod",
    "fchown", "fchownat", "chown", "lchown",
    "unlink", "unlinkat",
    "mkdir", "mkdirat", "rmdir",
    "rename", "renameat", "renameat2",
    "link", "linkat",
    "symlink", "symlinkat",
    "truncate", "ftruncate", "truncate64", "ftruncate64",
    NULL,
};

static const char *const fs_misc_syscalls[] = {
    "dup", "dup2", "dup3",
    "fcntl", "ioctl",
    "fsync", "fdatasync",
    "getdents", "getdents64",
    "pipe", "pipe2",
    "close_range", "closefrom",
    "chdir", "fchdir",
    "utime", "utimes", "futimesat", "utimensat",
    NULL,
};

static const char *const network_syscalls[] = {
    "socket", "socketpair",
    "bind", "listen", "accept", "accept4", "connect",
    "getsockopt", "setsockopt",
    "getsockname", "getpeername",
    "shutdown",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    NULL,
};

static const char *const event_syscalls[] = {
    "poll", "ppoll", "select", "pselect6",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "epoll_pwait2",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "eventfd", "eventfd2",
    "signalfd4",
    "alarm", "setitimer", "getitimer",
    NULL,
};

static const char *const process_syscalls[] = {
    "clone", "clone3", "fork", "vfork",
    "wait4", "waitid",
    "kill", "tkill",
    "setpgid", "getpgid", "getsid", "setsid",
    "setgid", "setuid", "setgroups",
    "capget", "capset",
    NULL,
};

static const char *const privilege_syscalls[] = {
    "setgid", "setuid", "setgroups",
    NULL,
};

static int
allow_syscall(scmp_filter_ctx ctx, const char *name) {
    int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR)
        return 0; /* syscall not supported on this arch/kernel */

    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
    if (rc == -EEXIST)
        return 0;

    return rc;
}

static int
allow_syscalls(scmp_filter_ctx ctx, const char *const *names) {
    for (size_t i = 0; names[i] != NULL; i++) {
        if (allow_syscall(ctx, names[i]) < 0)
            return -1;
    }

    return 0;
}

int
seccomp_available(void) {
    return seccomp_api_get() > 0;
}

static int
install_filter(enum seccomp_process_type type) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (ctx == NULL)
        return -1;

    if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    /* Apply filter to the whole thread group, not just the caller */
    if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    /* Common syscalls for all processes */
    if (allow_syscalls(ctx, common_syscalls) < 0 ||
        allow_syscalls(ctx, event_syscalls) < 0 ||
        allow_syscalls(ctx, network_syscalls) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    /* Process-specific rules */
    switch (type) {
        case SECCOMP_PROCESS_MAIN:
            if (allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_write_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0 ||
                allow_syscalls(ctx, process_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_LOGGER:
            if (allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_write_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0 ||
                allow_syscalls(ctx, privilege_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_RESOLVER:
            if (allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_BINDER:
            /* Binder doesn't need to open/write files, just manage sockets */
            if (allow_syscalls(ctx, fs_misc_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;
    }

    if (seccomp_load(ctx) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return 0;
}

int
seccomp_install_filter(enum seccomp_process_type type) {
    const char *disable_env = getenv("SNIPROXY_DISABLE_SECCOMP");
    if (disable_env != NULL && disable_env[0] != '\0')
        return 0;

    if (!seccomp_available()) {
        errno = ENOSYS;
        return -1;
    }

    return install_filter(type);
}

#else /* !(__linux__ && HAVE_SECCOMP) */

int
seccomp_available(void) {
    return 0;
}

int
seccomp_install_filter(enum seccomp_process_type type) {
    (void)type;
    return 0;
}

#endif
