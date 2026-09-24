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
#include <stdio.h>
#include <stdlib.h>

/* The lists name each call in all its forms: 32-bit ABIs such as i386 and
 * ARM have their own for some of them (mmap2, fcntl64, getuid32, _llseek,
 * the *_time64 calls). allow_syscall() skips the names the architecture
 * does not have, and a 32-bit libc calls the other forms, so a list with
 * only the 64-bit names kills every process on those systems. */
static const char *const common_syscalls[] = {
    "read", "write", "readv", "writev", "pwrite64", "pread64",
    "pwritev", "preadv",
    "close", "lseek", "_llseek", "fstat", "fstat64",
    "brk", "madvise", "mmap", "mmap2", "mprotect", "mremap", "munmap",
    "clock_gettime", "clock_gettime64", "clock_getres",
    "clock_getres_time64", "clock_nanosleep", "clock_nanosleep_time64",
    "gettimeofday", "nanosleep", "time",
    "getpid", "getppid", "gettid", "getrusage",
    "getuid", "getuid32", "geteuid", "geteuid32", "getgid", "getgid32",
    "getegid", "getegid32", "getgroups", "getgroups32", "getcwd",
    "uname", "sysinfo",
    "futex", "futex_time64", "set_robust_list", "set_tid_address",
    "sched_yield", "sched_getaffinity", "sched_getparam", "sched_setscheduler",
    "restart_syscall", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigreturn", "sigaltstack", "tgkill", "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "prctl", "prlimit64", "getrlimit", "ugetrlimit", "setrlimit",
    "getrandom",
    "umask",
    "exit", "exit_group",
    NULL,
};

static const char *const fs_read_syscalls[] = {
    "open", "openat", "openat2",
    "stat", "stat64", "lstat", "lstat64", "newfstatat", "fstatat64",
    "fstatfs", "fstatfs64", "statfs", "statfs64", "statx",
    "readlink", "readlinkat",
    "faccessat", "access",
    NULL,
};

static const char *const fs_write_syscalls[] = {
    "fchmod", "fchmodat", "chmod",
    "fchown", "fchown32", "fchownat", "chown", "chown32", "lchown",
    "lchown32",
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
    "fcntl", "fcntl64", "ioctl",
    "fsync", "fdatasync",
    "getdents", "getdents64",
    "pipe", "pipe2",
    "close_range", "closefrom",
    "chdir", "fchdir",
    "utime", "utimes", "futimesat", "utimensat", "utimensat_time64",
    NULL,
};

static const char *const network_syscalls[] = {
    "socket", "socketpair",
    "bind", "listen", "accept", "accept4", "connect",
    "getsockopt", "setsockopt",
    "getsockname", "getpeername",
    "shutdown",
    "sendto", "send", "recvfrom", "recv", "sendmsg", "recvmsg",
    "sendmmsg", "recvmmsg", "recvmmsg_time64",
    NULL,
};

/* Restricted network subset for the logger child: IPC over its AF_UNIX
 * socketpair plus syslog (openlog needs socket+connect, syslog needs
 * sendto).  Does not include bind, listen, accept, recvfrom, socketpair,
 * sendmmsg, recvmmsg, or getpeername. */
static const char *const logger_network_syscalls[] = {
    "socket", "connect",
    "sendto", "send", "sendmsg", "recvmsg",
    "getsockopt", "setsockopt",
    "getsockname",
    "shutdown",
    NULL,
};

/* Restricted network subset for the binder child: it binds privileged
 * ports and passes the resulting sockets back over its IPC channel via
 * sendmsg/recvmsg; it never listens or accepts.  socket/connect/sendto
 * are kept because, after disinheriting the logger process, the binder
 * logs its own errors directly, which reaches vsyslog() when error_log
 * uses syslog.  Excludes listen, accept, accept4, recvfrom, sendmmsg,
 * recvmmsg, getsockname, getpeername, and socketpair (created in the
 * parent before fork). */
static const char *const binder_network_syscalls[] = {
    "socket", "connect",
    "bind", "setsockopt",
    "sendto", "send", "sendmsg", "recvmsg",
    NULL,
};

static const char *const event_syscalls[] = {
    "poll", "ppoll", "ppoll_time64", "select", "_newselect", "pselect6",
    "pselect6_time64",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "epoll_pwait2",
    "timerfd_create", "timerfd_settime", "timerfd_settime64",
    "timerfd_gettime", "timerfd_gettime64",
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
    "setgid", "setgid32", "setuid", "setuid32", "setgroups", "setgroups32",
    "capget", "capset",
    /* Helper processes forked at runtime to replace a dead child run
     * under the inherited main filter until they install their own,
     * which libseccomp loads via seccomp(2). Allowing it here cannot
     * loosen the sandbox since a second filter only restricts further. */
    "seccomp",
    NULL,
};

static const char *const privilege_syscalls[] = {
    "setgid", "setgid32", "setuid", "setuid32", "setgroups", "setgroups32",
    NULL,
};

/* ARM needs the instruction cache flushed after PCRE2 JIT writes code,
 * which the main process does when a reload compiles the tables. */
static const char *const jit_syscalls[] = {
    "cacheflush",
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
        allow_syscalls(ctx, event_syscalls) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    /* Process-specific rules */
    switch (type) {
        case SECCOMP_PROCESS_MAIN:
            if (allow_syscalls(ctx, network_syscalls) < 0 ||
                allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_write_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0 ||
                allow_syscalls(ctx, process_syscalls) < 0 ||
                allow_syscalls(ctx, jit_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_LOGGER:
            if (allow_syscalls(ctx, logger_network_syscalls) < 0 ||
                allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_write_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0 ||
                allow_syscalls(ctx, privilege_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_RESOLVER:
            if (allow_syscalls(ctx, network_syscalls) < 0 ||
                allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0) {
                seccomp_release(ctx);
                return -1;
            }
            break;

        case SECCOMP_PROCESS_BINDER:
            /* fs_read is needed by the binder's own error logging: after it
             * disinherits the logger process it formats messages locally,
             * and both the timestamp path (localtime/strftime) and vsyslog
             * read /etc/localtime (openat + per-call newfstatat). Without it
             * the first err() would be killed by SCMP_ACT_KILL_PROCESS. */
            if (allow_syscalls(ctx, binder_network_syscalls) < 0 ||
                allow_syscalls(ctx, fs_read_syscalls) < 0 ||
                allow_syscalls(ctx, fs_misc_syscalls) < 0) {
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
    if (disable_env != NULL && disable_env[0] != '\0') {
        fprintf(stderr, "WARNING: seccomp sandbox disabled via "
                "SNIPROXY_DISABLE_SECCOMP environment variable\n");
        return 0;
    }

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

/*
 * Linux capabilities. A listener with "source client" needs CAP_NET_RAW
 * for IP_TRANSPARENT after the main process has dropped root, so the main
 * process keeps that single capability across setuid(). Helpers forked
 * once privileges are dropped give it up again.
 */
#if defined(__linux__) && defined(HAVE_LINUX_CAPABILITY_H)

#include <linux/capability.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int
caps_set(int keep_net_raw) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    if (keep_net_raw) {
        data[CAP_TO_INDEX(CAP_NET_RAW)].permitted = CAP_TO_MASK(CAP_NET_RAW);
        data[CAP_TO_INDEX(CAP_NET_RAW)].effective = CAP_TO_MASK(CAP_NET_RAW);
    }
    return (int)syscall(SYS_capset, &hdr, data);
}

int
caps_keep_on_setuid(void) {
    return prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
}

int
caps_limit_to_net_raw(void) {
    if (caps_set(1) < 0)
        return -1;
    return prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
}

int
caps_drop_all(void) {
    return caps_set(0);
}

int
caps_drop_net_raw(void) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    int i = CAP_TO_INDEX(CAP_NET_RAW);

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &hdr, data) < 0)
        return -1;
    data[i].effective &= ~CAP_TO_MASK(CAP_NET_RAW);
    data[i].permitted &= ~CAP_TO_MASK(CAP_NET_RAW);
    data[i].inheritable &= ~CAP_TO_MASK(CAP_NET_RAW);
    return (int)syscall(SYS_capset, &hdr, data);
}

#else /* !(__linux__ && HAVE_LINUX_CAPABILITY_H) */

#include <errno.h>

int
caps_keep_on_setuid(void) {
#ifdef __linux__
    /* Only reached with a "source client" listener, which cannot work
     * without keeping CAP_NET_RAW. */
    errno = ENOSYS;
    return -1;
#else
    return 0;
#endif
}

int
caps_limit_to_net_raw(void) {
    return 0;
}

int
caps_drop_all(void) {
    return 0;
}

int
caps_drop_net_raw(void) {
    return 0;
}

#endif
