/*
 * Copyright (c) 2011-2014, Dustin Lundquist <dustin@null-ptr.net>
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
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <errno.h>
#include <stddef.h>
#ifdef __OpenBSD__
#include <limits.h>
#include <libgen.h>
#include <sys/un.h>
#endif
#include <ev.h>
#include "binder.h"
#include "config.h"
#include "connection.h"
#include "listener.h"
#include "resolv.h"
#include "logger.h"
#include "tls.h"


static void usage(void);
static void daemonize(void);
static void write_pidfile(const char *, pid_t);
static void set_limits(rlim_t);
static void drop_perms(const char* username, const char* groupname);
static void perror_exit(const char *);
static void signal_cb(struct ev_loop *, struct ev_signal *, int revents);
static void rename_main_process(void);

#ifdef __OpenBSD__
struct openbsd_unveil_data {
    const char *permissions;
    int allow_create;
};

static void openbsd_unveil_parent(const char *path, const char *permissions);
static void openbsd_unveil_path(const char *path, const char *permissions,
        int allow_create);
static void openbsd_logger_unveil_cb(const char *path, void *userdata);
static void openbsd_unveil_address(const struct Address *address,
        const char *permissions, int allow_create);
#endif


static const char *sniproxy_version = PACKAGE_VERSION;
static const char *default_username = "daemon";
static struct Config *config;
static struct ev_signal sighup_watcher;
static struct ev_signal sigusr1_watcher;
static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;


#ifdef __OpenBSD__
static void
openbsd_unveil_parent(const char *path, const char *permissions) {
    char *copy;
    char *parent;
    char perms_buf[16];
    size_t len;

    if (path == NULL || permissions == NULL)
        return;

    copy = strdup(path);
    if (copy == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    parent = dirname(copy);
    if (parent != NULL && parent[0] != '\0') {
        len = strlen(permissions);
        if (len >= sizeof(perms_buf)) {
            fprintf(stderr, "unveil %s: permission string too long\n", parent);
            free(copy);
            exit(EXIT_FAILURE);
        }
        memcpy(perms_buf, permissions, len);
        perms_buf[len] = '\0';
        if (strchr(perms_buf, 'x') == NULL) {
            if (len + 1 >= sizeof(perms_buf)) {
                fprintf(stderr, "unveil %s: permission string too long\n", parent);
                free(copy);
                exit(EXIT_FAILURE);
            }
            perms_buf[len++] = 'x';
            perms_buf[len] = '\0';
        }

        if (unveil(parent, perms_buf) == -1) {
            fprintf(stderr, "unveil %s: %s\n", parent, strerror(errno));
            free(copy);
            exit(EXIT_FAILURE);
        }
    }

    free(copy);
}

static void
openbsd_unveil_path(const char *path, const char *permissions, int allow_create) {
    if (path == NULL || permissions == NULL)
        return;

    if (path[0] == '\0')
        return;

    if (unveil(path, permissions) == -1) {
        if (!(allow_create && errno == ENOENT)) {
            fprintf(stderr, "unveil %s: %s\n", path, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (allow_create)
        openbsd_unveil_parent(path, permissions);
}

static void
openbsd_logger_unveil_cb(const char *path, void *userdata) {
    const struct openbsd_unveil_data *data = userdata;

    if (data == NULL)
        return;

    openbsd_unveil_path(path, data->permissions, data->allow_create);
}

static void
openbsd_unveil_address(const struct Address *address, const char *permissions,
        int allow_create) {
    const struct sockaddr *sa;
    socklen_t sa_len;
    const struct sockaddr_un *sun;
    size_t max_len;
    size_t path_len;
    char path_buf[PATH_MAX];

    if (address == NULL || permissions == NULL)
        return;

    if (!address_is_sockaddr(address))
        return;

    sa = address_sa(address);
    sa_len = address_sa_len(address);
    if (sa == NULL || sa_len <= (socklen_t)offsetof(struct sockaddr_un, sun_path))
        return;

    if (sa->sa_family != AF_UNIX)
        return;

    sun = (const struct sockaddr_un *)sa;
    max_len = (size_t)sa_len - offsetof(struct sockaddr_un, sun_path);
    if (max_len == 0)
        return;

    if (sun->sun_path[0] == '\0')
        return;

    path_len = strnlen(sun->sun_path, max_len);
    if (path_len == 0 || path_len >= sizeof(path_buf))
        return;

    memcpy(path_buf, sun->sun_path, path_len);
    path_buf[path_len] = '\0';

    openbsd_unveil_path(path_buf, permissions, allow_create);

    if (!allow_create) {
        const char *parent_permissions = strchr(permissions, 'r') != NULL ? "rx" : "x";
        openbsd_unveil_parent(path_buf, parent_permissions);
    }
}

#endif


int
main(int argc, char **argv) {
    const char *config_file = "/etc/sniproxy.conf";
    int background_flag = 1;
    rlim_t max_nofiles = 65536;
    int opt;
    int allow_tls10 = 0;

    logger_prepare_process_title(argc, argv);

    while ((opt = getopt(argc, argv, "fc:n:VT")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'f': /* foreground */
                background_flag = 0;
                break;
            case 'n':
                max_nofiles = strtoul(optarg, NULL, 10);
                break;
            case 'V':
                printf("sniproxy %s\n", sniproxy_version);
                return EXIT_SUCCESS;
            case 'T':
                allow_tls10 = 1;
                break;
            default:
                usage();
                return EXIT_FAILURE;
        }
    }

#ifdef __OpenBSD__
    openbsd_unveil_path(config_file, "r", 0);
#endif

    if (allow_tls10)
        tls_set_min_client_hello_version(3, 1);

    config = init_config(config_file, EV_DEFAULT);
    if (config == NULL) {
        fprintf(stderr, "Unable to load %s\n", config_file);
        usage();
        return EXIT_FAILURE;
    }

#ifdef __OpenBSD__
    {
        struct openbsd_unveil_data data = {
            .permissions = "rwc",
            .allow_create = 1,
        };
        struct Listener *listener;
        struct Table *table;

        if (config->pidfile != NULL)
            openbsd_unveil_path(config->pidfile, "rwc", 1);

        logger_for_each_file_sink(openbsd_logger_unveil_cb, &data);

        listener = SLIST_FIRST(&config->listeners);
        while (listener != NULL) {
            openbsd_unveil_address(listener->address, "rwc", 1);
            openbsd_unveil_address(listener->fallback_address, "rw", 0);
            openbsd_unveil_address(listener->source_address, "rwc", 0);
            listener = SLIST_NEXT(listener, entries);
        }

        table = SLIST_FIRST(&config->tables);
        while (table != NULL) {
            struct Backend *backend = STAILQ_FIRST(&table->backends);
            while (backend != NULL) {
                openbsd_unveil_address(backend->address, "rw", 0);
                backend = STAILQ_NEXT(backend, entries);
            }
            table = SLIST_NEXT(table, entries);
        }

        if (unveil(NULL, NULL) == -1) {
            perror("unveil");
            exit(EXIT_FAILURE);
        }

        if (pledge("stdio getpw inet dns rpath proc id wpath cpath unix", NULL) == -1) {
            fprintf(stderr, "%s: pledge: %s\n", argv[0], strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
#endif

    /* ignore SIGPIPE, or it will kill us */
    signal(SIGPIPE, SIG_IGN);

    if (background_flag) {
        if (config->pidfile != NULL)
            remove(config->pidfile);

        daemonize();


        if (config->pidfile != NULL)
            write_pidfile(config->pidfile, getpid());
    }

#ifdef __OpenBSD__
    if (logger_process_is_active()) {
        if (pledge("stdio getpw inet dns rpath proc id unix", NULL) == -1) {
            fprintf(stderr, "%s: pledge: %s\n", argv[0], strerror(errno));
            exit(EXIT_FAILURE);
        }
        logger_parent_notify_fs_locked();
    }
#endif

    start_binder();

    set_limits(max_nofiles);

    connections_set_per_ip_connection_rate(config->per_ip_connection_rate);

    connections_set_dns_query_limit(config->resolver.max_concurrent_queries);

    init_listeners(&config->listeners, &config->tables, EV_DEFAULT);

    /* Drop permissions only when we can */
    drop_perms(config->user ? config->user : default_username, config->group);
    rename_main_process();

    ev_signal_init(&sighup_watcher, signal_cb, SIGHUP);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sighup_watcher);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    resolv_init(EV_DEFAULT, config->resolver.nameservers,
            config->resolver.search, config->resolver.mode,
            config->resolver.dnssec_validation_mode);

    init_connections();

    ev_run(EV_DEFAULT, 0);

    free_connections(EV_DEFAULT);
    resolv_shutdown(EV_DEFAULT);

    free_config(config, EV_DEFAULT);

    stop_binder();

    return 0;
}

static void
daemonize(void) {
#if defined(HAVE_DAEMON) || defined(__OpenBSD__)
    if (daemon(0, 0) < 0)
        perror_exit("daemon()");
#else
    pid_t pid;

    /* daemon(0,0) part */
    pid = fork();
    if (pid < 0)
        perror_exit("fork()");
    else if (pid != 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        perror_exit("setsid()");

    if (chdir("/") < 0)
        perror_exit("chdir()");

    if (freopen("/dev/null", "r", stdin) == NULL)
        perror_exit("freopen(stdin)");

    if (freopen("/dev/null", "a", stdout) == NULL)
        perror_exit("freopen(stdout)");

    if (freopen("/dev/null", "a", stderr) == NULL)
        perror_exit("freopen(stderr)");

    pid = fork();
    if (pid < 0)
        perror_exit("fork()");
    else if (pid != 0)
        exit(EXIT_SUCCESS);
#endif

    /* local part */
    /*
     * Use a restrictive umask so any files we create (pid files, debug
     * dumps, log files before permissions are adjusted, etc.) are not left
     * world or group accessible by default.  Individual file creation code
     * will relax permissions explicitly when needed.
     */
    umask(077);
    signal(SIGHUP, SIG_IGN);

    ev_default_fork();

    return;
}

/**
 * Raise file handle limit to reasonable level
 * At some point we should make this a config parameter
 */
static void
set_limits(rlim_t max_nofiles) {
    struct rlimit fd_limit = {
        .rlim_cur = max_nofiles,
        .rlim_max = max_nofiles,
    };

    int result = setrlimit(RLIMIT_NOFILE, &fd_limit);
    if (result < 0)
        warn("Failed to set file handle limit: %s", strerror(errno));
}

static void
drop_perms(const char *username, const char *groupname) {
    /* check if we are already an unprivileged user */
    if (getuid() != 0)
        return;

    errno = 0;
    struct passwd *user = getpwnam(username);
    if (errno)
        fatal("getpwnam(): %s", strerror(errno));
    else if (user == NULL)
        fatal("getpwnam(): user %s does not exist", username);

    gid_t gid = user->pw_gid;

    if (groupname != NULL) {
      errno = 0;
      struct group *group = getgrnam(groupname);
      if (errno)
        fatal("getgrnam(): %s", strerror(errno));
      else if (group == NULL)
        fatal("getgrnam(): group %s does not exist", groupname);

      gid = group->gr_gid;
    }

    if (logger_drop_privileges(user->pw_uid, gid) < 0)
        fatal("logger_drop_privileges(): %s", strerror(errno));

    /* drop any supplementary groups */
    if (setgroups(1, &gid) < 0)
        fatal("setgroups(): %s", strerror(errno));

    /* set the main gid */
    if (setgid(gid) < 0)
        fatal("setgid(): %s", strerror(errno));

    if (setuid(user->pw_uid) < 0)
        fatal("setuid(): %s", strerror(errno));
}

static void
rename_main_process(void) {
#ifdef __linux__
    (void)prctl(PR_SET_NAME, "sniproxy-mainloop", 0, 0, 0);
#endif
#if defined(HAVE_SETPROCTITLE) && !defined(__OpenBSD__)
    setproctitle("sniproxy-mainloop");
#endif
}

static void
perror_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void
usage(void) {
    fprintf(stderr, "Usage: sniproxy [-c <config>] [-f] [-n <max file descriptor limit>] [-V] [-T]\n");
    fprintf(stderr, "       -T allow TLS 1.0 client hellos\n");
}

static void
write_pidfile(const char *path, pid_t pid) {
    int open_flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif

    int fd = -1;
    FILE *fp = NULL;

    fd = open(path, open_flags, 0600);
    if (fd < 0) {
        perror("open");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        perror("fstat");
        close(fd);
        errno = saved_errno;
        return;
    }

    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        perror("write_pidfile");
        close(fd);
        return;
    }

    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (fchmod(fd, st.st_mode & ~(S_IWGRP | S_IWOTH)) != 0)
            perror("fchmod");
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        int saved_errno = errno;
        perror("fdopen");
        errno = saved_errno;
        goto cleanup;
    }

    fprintf(fp, "%d\n", pid);

cleanup:
    if (fp != NULL)
        fclose(fp);
    else if (fd >= 0)
        close(fd);

}

static void
signal_cb(struct ev_loop *loop, struct ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGHUP:
                reopen_loggers();
                reload_config(config, loop);
                break;
            case SIGUSR1:
                print_connections();
                break;
            case SIGINT:
            case SIGTERM:
                ev_unloop(loop, EVUNLOOP_ALL);
        }
    }
}
