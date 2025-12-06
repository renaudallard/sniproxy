/*
 * Copyright (c) 2011-2014, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdint.h>
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
#include "ipc_crypto.h"
#include "http.h"
#include "tls.h"
#include "seccomp_filter.h"


static void usage(void);
static void daemonize(void);
static void write_pidfile(const char *, pid_t);
static void set_limits(rlim_t);
static void drop_perms(const char* username, const char* groupname);
static void perror_exit(const char *);
static void signal_cb(struct ev_loop *, struct ev_signal *, int revents);
static void rename_main_process(void);
static void apply_mainloop_settings(struct ev_loop *, const struct Config *);
static size_t effective_max_connections(const struct Config *);
static int parse_min_tls_version(const char *value, uint8_t *major, uint8_t *minor);

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
static rlim_t configured_fd_limit;
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
        fatal("unveil %s: strdup failed: %s", path, strerror(errno));
    }

    parent = dirname(copy);
    if (parent != NULL && parent[0] != '\0') {
        len = strlen(permissions);
        if (len >= sizeof(perms_buf)) {
            fatal("unveil %s: permission string too long", parent);
        }
        memcpy(perms_buf, permissions, len);
        perms_buf[len] = '\0';
        if (strchr(perms_buf, 'x') == NULL) {
            if (len + 1 >= sizeof(perms_buf)) {
                fatal("unveil %s: permission string too long", parent);
            }
            perms_buf[len++] = 'x';
            perms_buf[len] = '\0';
        }

        if (unveil(parent, perms_buf) == -1) {
            fatal("unveil %s failed: %s", parent, strerror(errno));
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
            fatal("unveil %s failed: %s", path, strerror(errno));
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
    uint8_t min_tls_major = 3;
    uint8_t min_tls_minor = 3;
    struct ev_loop *loop = NULL;

    logger_prepare_process_title(argc, argv);

    if (ipc_crypto_system_init() < 0) {
        fatal("Unable to initialize IPC crypto");
    }

    while ((opt = getopt(argc, argv, "fc:n:T:Vd")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'f': /* foreground */
                background_flag = 0;
                break;
            case 'n':
                {
                    errno = 0;
                    char *endptr = NULL;
                    unsigned long value = strtoul(optarg, &endptr, 10);
                    if (errno != 0 || endptr == optarg || (endptr != NULL && *endptr != '\0')) {
                        err("Invalid file descriptor limit '%s'", optarg);
                        return EXIT_FAILURE;
                    }
                    if (value == 0) {
                        err("max file descriptor limit must be > 0");
                        return EXIT_FAILURE;
                    }
                    if (value > RLIM_INFINITY)
                        value = RLIM_INFINITY;
                    max_nofiles = (rlim_t)value;
                }
                break;
            case 'V':
                printf("sniproxy %s\n", sniproxy_version);
                return EXIT_SUCCESS;
            case 'T':
                {
                    uint8_t parsed_major;
                    uint8_t parsed_minor;
                    if (!parse_min_tls_version(optarg, &parsed_major, &parsed_minor)) {
                        err("Invalid TLS version '%s'. Supported values: 1.0, 1.1, 1.2, 1.3", optarg);
                        return EXIT_FAILURE;
                    }
                    min_tls_major = parsed_major;
                    min_tls_minor = parsed_minor;
                }
                break;
            case 'd': /* debug */
                set_resolver_debug(1);
                fprintf(stderr, "Resolver debug logging enabled\n");
                break;
            default:
                err("Invalid command line arguments");
                usage();
                return EXIT_FAILURE;
        }
    }

#ifdef __OpenBSD__
    openbsd_unveil_path(config_file, "r", 0);
#endif

    /* Config file permissions are checked in init_config() using fstat() */

    tls_set_min_client_hello_version(min_tls_major, min_tls_minor);

    unsigned int loop_flags = 0;
#ifdef EVFLAG_FORKCHECK
    loop_flags |= EVFLAG_FORKCHECK;
#endif
#ifdef EVFLAG_NOENV
    loop_flags |= EVFLAG_NOENV;
#endif
#ifdef __linux__
#ifdef EVFLAG_SIGNALFD
    loop_flags |= EVFLAG_SIGNALFD;
#endif
#ifdef EVFLAG_NOINOTIFY
    loop_flags |= EVFLAG_NOINOTIFY;
#endif
#endif
    loop = ev_default_loop(loop_flags);
    if (loop == NULL) {
        fatal("Unable to initialize libev main loop");
    }

    config = init_config(config_file, loop, 1);
    if (config == NULL) {
        err("Unable to load %s", config_file);
        usage();
        return EXIT_FAILURE;
    }

    apply_mainloop_settings(loop, config);

#ifdef DEBUG
    warn("SECURITY WARNING: sniproxy built with DEBUG; stack traces and memory addresses may be logged. Not for production use.");
#endif

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

        /* Unveil temp directories for print_connections() debug output.
         * This is triggered by SIGUSR1 and needs write access to create
         * temporary connection dump files. */
        const char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
        if (xdg_runtime != NULL && xdg_runtime[0] == '/') {
            /* SECURITY: Validate XDG_RUNTIME_DIR is not a symlink before unveiling.
             * An attacker could set this to a symlink pointing to a privileged
             * location. Using lstat() rejects symlinks, preventing this attack. */
            struct stat xdg_st;
            if (lstat(xdg_runtime, &xdg_st) == 0 &&
                S_ISDIR(xdg_st.st_mode) && !S_ISLNK(xdg_st.st_mode) &&
                xdg_st.st_uid == getuid()) {
                /* XDG_RUNTIME_DIR/sniproxy for user-specific temp files */
                char xdg_path[PATH_MAX];
                if (snprintf(xdg_path, sizeof(xdg_path), "%s/sniproxy",
                            xdg_runtime) < (int)sizeof(xdg_path)) {
                    openbsd_unveil_path(xdg_path, "rwc", 1);
                }
            }
        }
        /* System-wide temp directory */
        openbsd_unveil_path("/var/run/sniproxy", "rwc", 1);
        /* User-specific fallback temp directory */
        char tmp_path[PATH_MAX];
        if (snprintf(tmp_path, sizeof(tmp_path), "/tmp/sniproxy-%u",
                    getuid()) < (int)sizeof(tmp_path)) {
            openbsd_unveil_path(tmp_path, "rwc", 1);
        }

        /* Allow resolver child to read the default CA bundle */
        openbsd_unveil_path("/etc/ssl/cert.pem", "r", 0);

        if (unveil(NULL, NULL) == -1) {
            fatal("unveil commit failed: %s", strerror(errno));
        }

        if (pledge("stdio getpw inet dns rpath proc id wpath cpath unix", NULL) == -1) {
            fatal("main: pledge failed: %s", strerror(errno));
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
            fatal("main: pledge failed: %s", strerror(errno));
        }
        logger_parent_notify_fs_locked();
    }
#endif

    start_binder();

    set_limits(max_nofiles);
    configured_fd_limit = max_nofiles;

    connections_set_per_ip_connection_rate(config->per_ip_connection_rate);
    connections_set_global_limit(effective_max_connections(config));

    connections_set_dns_query_per_client_limit(config->resolver.max_queries_per_client);
    connections_set_dns_query_limit(config->resolver.max_concurrent_queries);
    connections_set_buffer_limits(config->client_buffer_limit,
            config->server_buffer_limit);
    http_set_max_headers(config->http_max_headers);

    init_listeners(&config->listeners, &config->tables, loop);

    /* Drop permissions only when we can */
    drop_perms(config->user ? config->user : default_username, config->group);
    rename_main_process();

#ifdef __OpenBSD__
    /* Tighten pledge after dropping privileges - no longer need getpw */
    if (pledge("stdio inet dns rpath proc id unix", NULL) == -1) {
        fatal("main: pledge failed: %s", strerror(errno));
    }
#endif

    ev_signal_init(&sighup_watcher, signal_cb, SIGHUP);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(loop, &sighup_watcher);
    ev_signal_start(loop, &sigusr1_watcher);
    ev_signal_start(loop, &sigint_watcher);
    ev_signal_start(loop, &sigterm_watcher);

    resolv_init(loop, config->resolver.nameservers,
            config->resolver.search, config->resolver.mode,
            config->resolver.dnssec_validation_mode);

    init_connections();

    /* Install seccomp filter after all initialization is complete */
    if (seccomp_available()) {
        if (seccomp_install_filter(SECCOMP_PROCESS_MAIN) < 0) {
            fatal("main: failed to install seccomp filter: %s", strerror(errno));
        }
    }

    ev_run(loop, 0);

    free_connections(loop);
    resolv_shutdown(loop);

    free_config(config, loop);

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

    /* check if we are already running as the requested user */
    if (getuid() != 0 || geteuid() != 0) {
        if (getuid() != user->pw_uid || geteuid() != user->pw_uid)
            fatal("Process UID does not match configured user %s", username);
        if (getgid() != gid || getegid() != gid)
            fatal("Process GID does not match configured gid %lu", (unsigned long)gid);
        return;
    }

    /* SECURITY: Drop main process privileges FIRST before communicating
     * with child processes over IPC. This prevents a window where the
     * main process has root and could be exploited if IPC is compromised.
     * Correct privilege dropping order per security best practices:
     * 1. setgroups() - clear supplementary groups
     * 2. setgid()    - drop group privileges
     * 3. setuid()    - drop user privileges (irreversible)
     * 4. Verify drop succeeded
     * 5. Then communicate with child processes */

    /* drop any supplementary groups */
    if (setgroups(1, &gid) < 0)
        fatal("setgroups(): %s", strerror(errno));

    /* set the main gid */
    if (setgid(gid) < 0)
        fatal("setgid(): %s", strerror(errno));

    /* set the main uid - this is irreversible */
    if (setuid(user->pw_uid) < 0)
        fatal("setuid(): %s", strerror(errno));

    /* verify privileges were actually dropped */
    if (getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0)
        fatal("Failed to drop privileges");

    /* Now that main process is unprivileged, tell logger child to drop too */
    if (logger_drop_privileges(user->pw_uid, gid) < 0)
        fatal("logger_drop_privileges(): %s", strerror(errno));
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
    fatal("%s: %s", msg, strerror(errno));
}

static void
usage(void) {
    fprintf(stderr, "Usage: sniproxy [-c <config>] [-f] [-n <max file descriptor limit>] [-V] [-T <min TLS version>] [-d]\n");
    fprintf(stderr, "       -T <1.0|1.1|1.2|1.3> set minimum TLS client hello version (default 1.2)\n");
    fprintf(stderr, "       -d enable resolver debug logging\n");
}

static void
apply_mainloop_settings(struct ev_loop *loop, const struct Config *cfg) {
    if (loop == NULL || cfg == NULL)
        return;

    ev_set_io_collect_interval(loop, cfg->io_collect_interval);
    ev_set_timeout_collect_interval(loop, cfg->timeout_collect_interval);
}

static size_t
effective_max_connections(const struct Config *cfg) {
    if (cfg == NULL)
        return 0;

    if (cfg->max_connections > 0)
        return cfg->max_connections;

    if (configured_fd_limit <= 0)
        return 0;

    size_t fd_budget = (size_t)configured_fd_limit;
    size_t headroom = fd_budget / 5; /* keep 20% for listeners, resolver, etc. */
    if (headroom < 256)
        headroom = 256;
    if (headroom >= fd_budget)
        return fd_budget > 1 ? fd_budget - 1 : 1;

    return fd_budget - headroom;
}

static int
parse_min_tls_version(const char *value, uint8_t *major, uint8_t *minor) {
    char *endptr = NULL;
    long parsed_major;
    long parsed_minor;

    if (value == NULL || major == NULL || minor == NULL)
        return 0;

    errno = 0;
    parsed_major = strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '.')
        return 0;

    if (parsed_major != 1)
        return 0;

    const char *minor_str = endptr + 1;
    if (*minor_str == '\0')
        return 0;

    errno = 0;
    parsed_minor = strtol(minor_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0')
        return 0;

    if (parsed_minor < 0 || parsed_minor > 3)
        return 0;

    *major = 3;
    *minor = (uint8_t)(parsed_minor + 1);

    return 1;
}

static void
write_pidfile(const char *path, pid_t pid) {
    /* Use O_EXCL to prevent opening existing files (hardlink attack protection) */
    int open_flags = O_WRONLY | O_CREAT | O_EXCL;
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
        if (errno == EEXIST) {
            fprintf(stderr, "PID file %s already exists (possible race or stale file)\n", path);
        } else {
            perror("open");
        }
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

    /* Validate file type and attributes for security */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "PID file is not a regular file\n");
        errno = EINVAL;
        close(fd);
        return;
    }

    /* Defense-in-depth: verify file was just created and we own it */
    if (st.st_nlink != 1) {
        fprintf(stderr, "PID file has unexpected link count: %lu\n",
                (unsigned long)st.st_nlink);
        errno = EINVAL;
        close(fd);
        return;
    }

    if (st.st_uid != getuid()) {
        fprintf(stderr, "PID file owned by unexpected UID: %u (expected %u)\n",
                (unsigned int)st.st_uid, (unsigned int)getuid());
        errno = EPERM;
        close(fd);
        return;
    }

    if (st.st_size != 0) {
        fprintf(stderr, "PID file has unexpected size: %lld\n",
                (long long)st.st_size);
        errno = EINVAL;
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
                apply_mainloop_settings(loop, config);
                connections_set_global_limit(effective_max_connections(config));
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
