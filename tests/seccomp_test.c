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

#if defined(__linux__) && defined(HAVE_SECCOMP)

#include <errno.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../src/seccomp_filter.h"

static int
test_allowed_operations(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(sv[0]);
        close(sv[1]);
        return 1;
    } else if (pid == 0) {
        close(sv[0]);
        if (write(sv[1], "x", 1) != 1)
            _exit(1);
        _exit(0);
    }

    close(sv[1]);
    char buf;
    if (read(sv[0], &buf, 1) != 1) {
        perror("read");
        close(sv[0]);
        return 1;
    }
    close(sv[0]);

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;

    return 0;
}

static int
test_blocked_ptrace(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        _exit(0);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        return (sig == SIGSYS || sig == SIGKILL) ? 0 : 1;
    }

    /* Returning normally would mean the disallowed syscall was not blocked */
    return 1;
}

/* Run fn in a child and check that the filter kills it */
static int
expect_killed(void (*fn)(void)) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        fn();
        _exit(0);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    return WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS ? 0 : 1;
}

static void
clone_new_user(void) {
#if defined(__s390__) || defined(__s390x__)
    /* The stack comes first there */
    pid_t pid = (pid_t)syscall(SYS_clone, 0, CLONE_NEWUSER | SIGCHLD, 0, 0, 0);
#else
    pid_t pid = (pid_t)syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
#endif
    if (pid == 0)
        _exit(0);
}

static void
netlink_netfilter(void) {
    (void)socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
}

static void
ioctl_tiocsti(void) {
    char c = 0;
    (void)ioctl(STDIN_FILENO, TIOCSTI, &c);
}

/* Under the main filter: no process in new namespaces, no netlink but
 * NETLINK_ROUTE, no TIOCSTI; clone3() fails with ENOSYS, so that libc
 * falls back to clone(), and other requests near TIOCSTI still reach
 * the kernel. */
static int
test_process_and_socket_limits(void) {
    if (expect_killed(clone_new_user) != 0)
        return 1;
    if (expect_killed(netlink_netfilter) != 0)
        return 1;
    if (expect_killed(ioctl_tiocsti) != 0)
        return 1;

#ifdef SYS_clone3
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS)
        return 1;
#endif

    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl < 0)
        return 1;
    close(nl);

    int fds[2];
    if (pipe(fds) < 0)
        return 1;
    static const unsigned long near[] = { TIOCGWINSZ, TIOCSWINSZ, FIONREAD };
    for (size_t i = 0; i < sizeof(near) / sizeof(near[0]); i++) {
        struct winsize ws = { 0 };
        (void)ioctl(fds[0], near[i], &ws);
    }
    close(fds[0]);
    close(fds[1]);

    return 0;
}

struct thread_sync_state {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int ready;
    int go;
};

static void *
ptrace_thread(void *arg) {
    struct thread_sync_state *state = arg;

    pthread_mutex_lock(&state->lock);
    state->ready = 1;
    pthread_cond_signal(&state->cond);
    while (!state->go)
        pthread_cond_wait(&state->cond, &state->lock);
    pthread_mutex_unlock(&state->lock);

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    return (void *)0;
}

static int
test_tsync_applies_to_threads(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        struct thread_sync_state state = {
            .lock = PTHREAD_MUTEX_INITIALIZER,
            .cond = PTHREAD_COND_INITIALIZER,
            .ready = 0,
            .go = 0,
        };

        pthread_t tid;
        if (pthread_create(&tid, NULL, ptrace_thread, &state) != 0)
            _exit(1);

        pthread_mutex_lock(&state.lock);
        while (!state.ready)
            pthread_cond_wait(&state.cond, &state.lock);
        pthread_mutex_unlock(&state.lock);

        if (seccomp_install_filter(SECCOMP_PROCESS_MAIN) < 0)
            _exit(1);

        pthread_mutex_lock(&state.lock);
        state.go = 1;
        pthread_cond_signal(&state.cond);
        pthread_mutex_unlock(&state.lock);

        pthread_join(tid, NULL);
        _exit(0);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        return (sig == SIGSYS || sig == SIGKILL) ? 0 : 1;
    }

    /* If the child returned normally, seccomp did not apply to pre-existing threads */
    return 1;
}

/* A child forked at runtime to replace a dead helper process inherits the
 * main filter and must still be able to install its own filter. */
static int
test_forked_child_can_install_filter(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        if (seccomp_install_filter(SECCOMP_PROCESS_MAIN) < 0)
            _exit(1);

        pid_t child = fork();
        if (child < 0)
            _exit(1);
        if (child == 0) {
            if (seccomp_install_filter(SECCOMP_PROCESS_RESOLVER) < 0)
                _exit(1);
            _exit(0);
        }

        int status;
        if (waitpid(child, &status, 0) < 0)
            _exit(1);
        _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;

    return 0;
}

static int
run_child_with_seccomp(int (*fn)(void)) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        if (seccomp_install_filter(SECCOMP_PROCESS_MAIN) < 0)
            _exit(1);
        _exit(fn());
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (!WIFEXITED(status))
        return 1;

    return WEXITSTATUS(status);
}

int
main(void) {
    unsetenv("SNIPROXY_DISABLE_SECCOMP");

    if (!seccomp_available())
        return 77;

    if (run_child_with_seccomp(test_allowed_operations) != 0)
        return 1;

    if (run_child_with_seccomp(test_blocked_ptrace) != 0)
        return 1;

    if (run_child_with_seccomp(test_process_and_socket_limits) != 0)
        return 1;

    if (test_tsync_applies_to_threads() != 0)
        return 1;

    if (test_forked_child_can_install_filter() != 0)
        return 1;

    return 0;
}

#else /* !(defined(__linux__) && defined(HAVE_SECCOMP)) */

#include <stdio.h>

int
main(void) {
    printf("seccomp_test skipped: requires Linux with libseccomp\n");
    return 77; /* Automake skip */
}

#endif /* defined(__linux__) && defined(HAVE_SECCOMP) */
