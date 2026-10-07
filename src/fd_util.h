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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

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

/* Close every descriptor from lowfd up */
static inline void
close_descriptors_from(int lowfd)
{
#ifdef HAVE_CLOSEFROM
    closefrom(lowfd);
#else
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0)
        max_fd = 256;

    for (int current = (int)max_fd - 1; current >= lowfd; current--)
        close(current);
#endif
}

/*
 * Prepare a freshly forked helper process. Its signal disposition is set
 * first: a helper forked after the parent started its libev signal
 * watchers inherits them, the watched signals either blocked for a
 * signalfd it does not own or pointing at a handler that writes to the
 * parent's event pipe, which is closed below. Reload and the connection
 * dump are the parent's business, so SIGHUP and SIGUSR1 are ignored and
 * signalling the whole process group, as "pkill -HUP sniproxy" does,
 * kills no helper. So is SIGINT, which Ctrl-C sends to the whole group:
 * the parent stops its helpers itself. SIGTERM and SIGCHLD get their
 * default action back so that termination works.
 *
 * Then move the IPC socket to fd 0, close every other inherited
 * descriptor except stdout and stderr, and point stdout or stderr at
 * /dev/null when the parent did not have them open. Keeping fd 1 and 2
 * occupied means a stray fprintf(stderr) or the crash handler write in a
 * sandboxed child can never land on a socket that reused those numbers,
 * while the child's messages still reach the parent's stderr in
 * foreground mode. Returns the IPC descriptor, which is always 0, or -1
 * on failure. Nothing here logs: the caller has not detached the
 * parent's logging state yet.
 */
static inline int
fd_child_setup(int fd)
{
    struct sigaction sa;
    sigset_t empty_mask;

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGHUP, &sa, NULL);
    (void)sigaction(SIGUSR1, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGCHLD, &sa, NULL);
    sigemptyset(&empty_mask);
    (void)sigprocmask(SIG_SETMASK, &empty_mask, NULL);

    if (fd < 0)
        return -1;

    if (fd != 0) {
        if (dup2(fd, 0) < 0)
            return -1;
        close(fd);
    }

    close_descriptors_from(3);

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

/*
 * Whether a listening socket gets SO_REUSEADDR. It lets a restart bind a
 * TCP port that still has connections in TIME_WAIT, and a specific
 * address next to a wildcard one. On Linux two UDP sockets that both have
 * it may bind the same address whoever owns them, so another user could
 * take a dtls listener's datagrams; the BSDs refuse that between users.
 */
static inline int
listen_socket_reuseaddr(int sock_type) {
#ifdef __linux__
    return sock_type == SOCK_STREAM;
#else
    (void)sock_type;
    return 1;
#endif
}
/* The name helper_crash_handler() gives the process, as "resolver child" */
static inline const char **
helper_crash_name(void)
{
    static const char *name = "helper";
    return &name;
}

/*
 * Whether a fault raised the signal: a fault happens again once the
 * handler returns, now with the default action, and its core keeps the
 * fault's details, while a signal sent by a process, with kill(), tgkill()
 * or sigqueue(), has to be raised again. Fault codes are positive, and
 * below SI_USER where that is not 0. macOS gives a sent fault signal a
 * fault code, and OpenBSD can give it the fault code an earlier process
 * left behind, so there every signal is raised again.
 */
static inline int
helper_signal_from_fault(const siginfo_t *info)
{
#if defined(__APPLE__) || defined(__OpenBSD__)
    (void)info;
    return 0;
#else
    return info != NULL && info->si_code > 0 &&
            (SI_USER == 0 || info->si_code < SI_USER);
#endif
}

/*
 * Say on stderr that a helper process crashed, and with which signal: the
 * main process cannot tell, as libev reaps its children. Only
 * async-signal-safe calls: write() to stderr and raise(), no IPC, no
 * allocation. SA_RESETHAND has restored the default action, under which
 * the helper then ends.
 */
static inline void
helper_crash_handler(int signum, siginfo_t *info,
        void *context __attribute__((unused)))
{
    const char *name = *helper_crash_name();
    const char *signame = "UNKNOWN";
    ssize_t unused_write;

    switch (signum) {
        case SIGSEGV:
            signame = "SIGSEGV (segmentation fault)";
            break;
        case SIGBUS:
            signame = "SIGBUS (bus error)";
            break;
        case SIGABRT:
            signame = "SIGABRT (abort)";
            break;
        case SIGILL:
            signame = "SIGILL (illegal instruction)";
            break;
        case SIGFPE:
            signame = "SIGFPE (floating point exception)";
            break;
        default:
            break;
    }

    unused_write = write(STDERR_FILENO, name, strlen(name));
    unused_write = write(STDERR_FILENO, " crashed with signal ",
            sizeof(" crashed with signal ") - 1);
    unused_write = write(STDERR_FILENO, signame, strlen(signame));
    unused_write = write(STDERR_FILENO, "\n", 1);
    (void)unused_write;

    if (!helper_signal_from_fault(info))
        raise(signum);
}

static inline void
helper_install_crash_handler(const char *name)
{
    struct sigaction sa;

    *helper_crash_name() = name;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = helper_crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
    (void)sigaction(SIGABRT, &sa, NULL);
    (void)sigaction(SIGILL, &sa, NULL);
    (void)sigaction(SIGFPE, &sa, NULL);
}

/*
 * Reap a helper process that has been told to exit, giving it up to a
 * second, then kill it: one that is stuck, or stopped, which SIGKILL ends
 * too, must not hold up the main process. A helper that cannot be
 * killed, a binder still running as root seen from the unprivileged main
 * process, is left to init rather than waited for.
 */
static inline void
helper_wait_exit(pid_t pid)
{
    const struct timespec step = { 0, 10000000L };

    for (int i = 0; i < 100; i++) {
        pid_t result = waitpid(pid, NULL, WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR))
            return;
        if (result == 0)
            nanosleep(&step, NULL);
    }

    if (kill(pid, SIGKILL) == 0)
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
}

#endif /* FD_UTIL_H */
