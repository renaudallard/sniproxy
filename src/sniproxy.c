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
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <errno.h>
#include <stddef.h>
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#ifdef HAVE_BSD_UNISTD_H
#include <bsd/unistd.h>
#endif
#include <libgen.h>
#ifdef __OpenBSD__
#include <limits.h>
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
#include "udp_connection.h"
#include "seccomp_filter.h"
#include "capsicum.h"
#include "address.h"
#include "table.h"
#include "backend.h"
#include "fd_util.h"


static void usage(void);
static void daemonize(void);
static int write_pidfile(const char *, pid_t);
static rlim_t set_limits(rlim_t);
static void drop_perms(const char* username, const char* groupname);
static void lookup_user(const char *, const char *, uid_t *, gid_t *);
static int config_uses_transparent_proxy(const struct Config *);
static void perror_exit(const char *);
static void signal_cb(struct ev_loop *, struct ev_signal *, int revents);
static void sigchld_cb(struct ev_loop *, struct ev_signal *, int revents);
static void early_signal_cb(int);
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
/* Cleared when root was dropped without keeping CAP_NET_RAW, so a
 * "source client" added by a reload cannot work until a restart. */
static int transparent_proxy_capable = 1;
static rlim_t configured_fd_limit;
static struct ev_signal sighup_watcher;
static struct ev_signal sigusr1_watcher;
static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;
/* A reload or dump requested before the event loop took the signals */
static volatile sig_atomic_t early_sighup = 0;
static volatile sig_atomic_t early_sigusr1 = 0;
static const char *pidfile_path_at_exit = NULL;

/* Remove a leftover pidfile only when the process it names is gone.
 * Returns -1 when the pid is alive, meaning another instance runs. */
static int
pidfile_remove_stale(const char *path) {
    int open_flags = O_RDONLY | O_NONBLOCK;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif

    /* O_NONBLOCK so a FIFO left at this path cannot hang the open,
     * O_NOFOLLOW so a symlink cannot point us at another file. */
    int fd = open(path, open_flags);
    if (fd < 0)
        return 0;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        /* Not a pidfile we could have written; leave it alone and let
         * write_pidfile() refuse the path. */
        close(fd);
        return 0;
    }

    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return 0;
    }

    char line[32];
    long pid = 0;
    if (fgets(line, sizeof(line), fp) != NULL) {
        char *end;
        errno = 0;
        pid = strtol(line, &end, 10);
        /* Anything but a pid in range is not ours: 0 and -1 would name
         * a process group or every process to kill(). */
        if (errno != 0 || end == line || pid <= 0 || pid > INT_MAX)
            pid = 0;
    }
    fclose(fp);

    /* Treat an existing pid as live; EPERM means it exists but belongs
     * to another user. A recycled pid is indistinguishable from a live
     * instance, in that case the operator must remove the file. */
    if (pid > 0 && (kill((pid_t)pid, 0) == 0 || errno == EPERM))
        return -1;

    notice("removing stale PID file %s", path);
    (void)remove(path);
    return 0;
}

static void
pidfile_cleanup(void) {
    if (pidfile_path_at_exit == NULL)
        return;
    (void)remove(pidfile_path_at_exit);
    pidfile_path_at_exit = NULL;
}


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

    /* A path that does not exist yet may still be created once unveiled,
     * so its directory needs no unveil of its own, which would open all
     * of it, as all of /var/run for a pidfile there */
    if (unveil(path, permissions) == -1) {
        if (!(allow_create && errno == ENOENT)) {
            fatal("unveil %s failed: %s", path, strerror(errno));
        }
    }
}

/*
 * Make the directory print_connections() will write its dump to, owned by
 * the user sniproxy runs as once privileges are dropped, and unveil only
 * it: an unveiled path that does not exist yet can be made a directory but
 * not filled, and unveiling its parent would open all of /tmp or
 * /var/run. The candidates are the two get_secure_temp_dir() can reach
 * under unveil, in its order and with its checks: it first looks at
 * $XDG_RUNTIME_DIR itself, which stays hidden.
 */
static void
openbsd_unveil_dump_dir(uid_t uid, gid_t gid) {
    char dirs[2][PATH_MAX];
    struct stat st;

    /* drop_perms() refuses a start without root as another user: make
     * nothing for it */
    if (geteuid() != 0 && geteuid() != uid)
        return;

    (void)strlcpy(dirs[0], "/var/run/sniproxy", sizeof(dirs[0]));
    (void)snprintf(dirs[1], sizeof(dirs[1]), "/tmp/sniproxy-%lu",
            (unsigned long)uid);

    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (mkdir(dirs[i], 0700) == 0 && geteuid() != uid &&
                chown(dirs[i], uid, gid) < 0) {
            warn("chown %s: %s", dirs[i], strerror(errno));
            continue;
        }

        if (lstat(dirs[i], &st) == 0 && S_ISDIR(st.st_mode) &&
                st.st_uid == uid &&
                (st.st_mode & (S_IRWXG | S_IRWXO)) == 0) {
            if (unveil(dirs[i], "rwc") == -1)
                fatal("unveil %s failed: %s", dirs[i], strerror(errno));
            return;
        }
    }
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


/* The descriptor a configuration path such as /dev/fd/7 names, or -1 */
static int
config_path_descriptor(const char *path) {
    static const char *const prefixes[] = { "/dev/fd/", "/proc/self/fd/" };

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t len = strlen(prefixes[i]);
        char *end;

        if (strncmp(path, prefixes[i], len) != 0)
            continue;

        errno = 0;
        long fd = strtol(path + len, &end, 10);
        if (errno == 0 && end != path + len && *end == '\0' &&
                fd > STDERR_FILENO && fd <= INT_MAX)
            return (int)fd;
    }

    return -1;
}

int
main(int argc, char **argv) {
    const char *config_file = "/etc/sniproxy.conf";
    int background_flag = 1;
    int test_config = 0;
    rlim_t max_nofiles = 65536;
    int opt;
    struct sigaction early;

    /* Until the event loop handles them, a SIGHUP or SIGUSR1 would kill
     * the process: note it instead, to be acted on once the loop runs */
    memset(&early, 0, sizeof(early));
    early.sa_handler = early_signal_cb;
    sigemptyset(&early.sa_mask);
    early.sa_flags = SA_RESTART;
    (void)sigaction(SIGHUP, &early, NULL);
    (void)sigaction(SIGUSR1, &early, NULL);
    uint8_t min_tls_major = 3;
    uint8_t min_tls_minor = 3;
    struct ev_loop *loop = NULL;

    /* Make sure the standard descriptors are open. Otherwise the first
     * descriptor this process creates takes the place of stdin, stdout or
     * stderr, and later output, from this process or from the helper
     * children that keep fd 1 and 2, would land on that descriptor. */
    for (int fd = 0; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) != -1)
            continue;

        int devnull = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
        if (devnull >= 0 && devnull != fd) {
            (void)dup2(devnull, fd);
            close(devnull);
        }
    }

    /* Before the helpers are forked, which inherit it */
    make_undumpable();

    logger_prepare_process_title(argc, argv);

    while ((opt = getopt(argc, argv, "fc:gn:tT:Vd")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'f': /* foreground */
                background_flag = 0;
                break;
            case 'n':
                {
                    if (optarg[0] == '-') {
                        err("Invalid file descriptor limit '%s'", optarg);
                        return EXIT_FAILURE;
                    }
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
                    max_nofiles = (rlim_t)value;
                }
                break;
            case 'g':
                config_set_allow_group_read(1);
                break;
            case 't':
                test_config = 1;
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

    /* Nothing above the standard descriptors is ours: one inherited from
     * whatever started sniproxy, a file opened as root for instance, would
     * otherwise stay open after the privilege drop. Only the one a -c
     * path such as /dev/fd/7, or <(...) in a shell, names is kept. This
     * comes before anything here opens a descriptor of its own. */
    int config_fd = config_path_descriptor(config_file);
    if (config_fd < 0) {
        close_descriptors_from(STDERR_FILENO + 1);
    } else {
        for (int fd = STDERR_FILENO + 1; fd < config_fd; fd++)
            (void)close(fd);
        close_descriptors_from(config_fd + 1);
    }

    if (ipc_crypto_system_init() < 0) {
        fatal("Unable to initialize IPC crypto");
    }

    /* Make the config path absolute, as a daemon moves to / and would then
     * open a relative path from there. Only its directory is resolved: a
     * symbolic link to the file itself is left for each reload to follow,
     * as with an absolute path. realpath() can return a directory below
     * one the user may not search, which is no use as a path. */
    char config_path_buf[PATH_MAX];
    if (config_file[0] != '/') {
        const char *slash = strrchr(config_file, '/');
        char dir[PATH_MAX];
        char real_dir[PATH_MAX];
        const char *error = NULL;
        struct stat st;
        int len;

        len = snprintf(dir, sizeof(dir), "%.*s",
                slash != NULL ? (int)(slash - config_file) : 1,
                slash != NULL ? config_file : ".");
        if (len < 0 || (size_t)len >= sizeof(dir)) {
            error = strerror(ENAMETOOLONG);
        } else if (realpath(dir, real_dir) == NULL ||
                stat(real_dir, &st) < 0) {
            error = strerror(errno);
        } else {
            len = snprintf(config_path_buf, sizeof(config_path_buf),
                    "%s/%s", strcmp(real_dir, "/") == 0 ? "" : real_dir,
                    slash != NULL ? slash + 1 : config_file);
            if (len < 0 || (size_t)len >= sizeof(config_path_buf))
                error = strerror(ENAMETOOLONG);
            else
                config_file = config_path_buf;
        }
        /* In the foreground the relative path keeps working */
        if (error != NULL && background_flag && !test_config)
            fatal("Unable to make configuration file path %s absolute: %s",
                    config_file, error);
    }

    /* The config file is unveiled together with every other resource once
     * it has been parsed.  Unveiling it here instead would start
     * restricting the process before init_config() opens the log files it
     * names, and those paths are only known after parsing, so opening them
     * would fail with ENOENT. */

    /* Config file permissions are checked in init_config() using fstat() */

    /* A daemon must not keep the directory it was started from busy.
     * daemon() moves to / too late for the logger, which init_config()
     * starts, and on OpenBSD it cannot once unveil() has been locked. */
    if (background_flag && !test_config) {
        if (chdir("/") < 0)
            fatal("chdir(/): %s", strerror(errno));
        logger_set_daemon_mode();
    }

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

    if (config_get_allow_group_read())
        warn("SECURITY WARNING: running with -g flag. "
             "Config file group-read (0640) is permitted. "
             "Ensure the config file group is restricted to "
             "the sniproxy user group.");

    if (test_config) {
        fprintf(stderr, "configuration file %s test is successful\n",
                config_file);
        free_config(config, loop);
        return EXIT_SUCCESS;
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

        /* Before the first unveil(), which hides every other path: the
         * password database, and where the dump directory is made */
        uid_t run_uid;
        gid_t run_gid;
        lookup_user(config->user ? config->user : default_username,
                config->group, &run_uid, &run_gid);

        /* The directory print_connections() writes the SIGUSR1 dump to */
        openbsd_unveil_dump_dir(run_uid, run_gid);

        /* Readable so that a SIGHUP reload can parse it again. */
        openbsd_unveil_path(config_file, "r", 0);

        /* The resolver child inherits this view, and c-ares reads the
         * system resolver configuration and the hosts file through it.
         * Without them it falls back to a server on 127.0.0.1. */
        static const char *const resolver_files[] = {
            "/etc/resolv.conf",
            "/etc/hosts",
        };
        for (size_t i = 0; i < sizeof(resolver_files) / sizeof(resolver_files[0]); i++)
            if (unveil(resolver_files[i], "r") == -1 && errno != ENOENT)
                fatal("unveil %s failed: %s", resolver_files[i], strerror(errno));

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


        /* Allow resolver child to read the default CA bundle */
        openbsd_unveil_path("/etc/ssl/cert.pem", "r", 0);

        if (unveil(NULL, NULL) == -1) {
            fatal("unveil commit failed: %s", strerror(errno));
        }

        /* chown is needed until drop_perms() has handed the log files
         * over to the unprivileged user with fchown(); the pledge after
         * the privilege drop no longer includes it. */
        if (pledge("stdio getpw inet dns rpath proc id wpath cpath chown unix sendfd recvfd", NULL) == -1) {
            fatal("main: pledge failed: %s", strerror(errno));
        }
        logger_parent_notify_pledged();
    }
#endif

    /* ignore SIGPIPE, or it will kill us */
    signal(SIGPIPE, SIG_IGN);

    if (background_flag) {
        if (config->pidfile != NULL &&
                pidfile_remove_stale(config->pidfile) < 0)
            fatal("PID file %s names a running process; "
                    "is another instance already running?", config->pidfile);

        daemonize();


        if (config->pidfile != NULL &&
                write_pidfile(config->pidfile, getpid()) == 0) {
            /* Register atexit so a fatal() between here and the normal
             * shutdown path still removes the pidfile. Only arm cleanup
             * when we actually created the file, so a failed write never
             * removes a pidfile owned by another instance. */
            pidfile_path_at_exit = config->pidfile;
            atexit(pidfile_cleanup);
        }
    }

#ifdef __OpenBSD__
    if (logger_process_is_active()) {
        /* cpath stays so the atexit handler can remove the pidfile;
         * unveil bounds it to the pre-unveiled paths (pidfile, temp
         * dir, etc.).  wpath is kept so the SIGUSR1 connection dump
         * (print_connections) can write its temp file; unveil bounds
         * writes to the temp directories. chown stays until the
         * privilege drop below has chowned the log files. */
        if (pledge("stdio getpw inet dns rpath wpath proc id cpath chown unix sendfd recvfd", NULL) == -1) {
            fatal("main: pledge failed: %s", strerror(errno));
        }
        logger_parent_notify_fs_locked();
    }
#endif

    start_binder();

    /* Seed binder allowlist with configured listener addresses so the binder
     * child will refuse unexpected bind requests. */
    struct Listener *binder_listener = SLIST_FIRST(&config->listeners);
    while (binder_listener != NULL) {
        const struct sockaddr *sa = address_sa(binder_listener->address);
        socklen_t sa_len = address_sa_len(binder_listener->address);
        if (sa != NULL && sa_len > 0) {
            if (binder_register_allowed_address(sa, (size_t)sa_len) < 0) {
                fatal("Failed to register listener address with binder");
            }
        }
        binder_listener = SLIST_NEXT(binder_listener, entries);
    }

    configured_fd_limit = set_limits(max_nofiles);

    connections_set_per_ip_connection_rate(config->per_ip_connection_rate);
    connections_set_per_ip_max_connections(config->per_ip_max_connections);
    connections_set_per_ip_ipv6_prefix(config->per_ip_ipv6_prefix);
    connections_set_global_limit(effective_max_connections(config));

    connections_set_dns_query_per_client_limit(config->resolver.max_queries_per_client);
    connections_set_dns_query_limit(config->resolver.max_concurrent_queries);
    connections_set_buffer_limits(config->client_buffer_limit,
            config->server_buffer_limit);
    connections_set_backend_acl(config->backend_acl_mode,
            &config->backend_acl_rules);
    connections_set_tcp_fastopen(config->tcp_fastopen);
    listeners_set_tcp_fastopen(config->tcp_fastopen);
    http_set_max_headers(config->http_max_headers);

    init_listeners(&config->listeners, &config->tables, loop);

    /* Drop permissions only when we can */
    drop_perms(config->user ? config->user : default_username, config->group);
    rename_main_process();

#ifdef __OpenBSD__
    /* Tighten pledge after dropping privileges - no longer need getpw or id.
     * cpath kept for the atexit pidfile removal; wpath kept so the SIGUSR1
     * connection dump (print_connections) can write its temp file; unveil
     * bounds both to the pidfile and temp directories. */
    if (pledge("stdio inet dns rpath wpath proc cpath unix sendfd recvfd", NULL) == -1) {
        fatal("main: pledge failed: %s", strerror(errno));
    }
#endif

    ev_signal_init(&sighup_watcher, signal_cb, SIGHUP);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_init(&sigchld_watcher, sigchld_cb, SIGCHLD);
    ev_signal_start(loop, &sighup_watcher);
    ev_signal_start(loop, &sigusr1_watcher);
    ev_signal_start(loop, &sigint_watcher);
    ev_signal_start(loop, &sigterm_watcher);
    ev_signal_start(loop, &sigchld_watcher);

    /* Hand the loop what arrived before it took the signals over */
    if (early_sighup)
        (void)raise(SIGHUP);
    if (early_sigusr1)
        (void)raise(SIGUSR1);

    if (resolv_init(loop, config->resolver.nameservers,
            config->resolver.search, config->resolver.mode,
            config->resolver.dnssec_validation_mode) < 0)
        fatal("Failed to initialize resolver");

    init_connections();
    udp_init_sessions();

    /* Install seccomp filter after all initialization is complete */
    if (seccomp_available()) {
        if (seccomp_install_filter(SECCOMP_PROCESS_MAIN) < 0) {
            fatal("main: failed to install seccomp filter: %s", strerror(errno));
        }
    }

#if defined(__FreeBSD__) && defined(HAVE_CAPSICUM)
    /* The main process stays out of capability mode: connect() is not
     * permitted there at all, and it has to reach arbitrary backends.
     * Limit the rights on its end of the IPC sockets instead so they
     * cannot be used to bind or connect elsewhere. */
    if (capsicum_available()) {
        logger_parent_capsicum_limit_rights();
        resolv_parent_capsicum_limit_rights();
        binder_parent_capsicum_limit_rights();
    }
#endif

    /* Start logger health check watchdog */
    if (logger_process_is_active())
        logger_start_health_check(loop);

    ev_run(loop, 0);

    logger_stop_health_check();
    udp_free_sessions(loop);
    free_connections(loop);
    resolv_shutdown(loop);

    if (config->pidfile != NULL)
        pidfile_cleanup();

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
        _exit(EXIT_SUCCESS);

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
        _exit(EXIT_SUCCESS);
#endif

    /* local part */
    /*
     * Use a restrictive umask so any files we create (pid files, debug
     * dumps, log files before permissions are adjusted, etc.) are not left
     * world or group accessible by default.  Individual file creation code
     * will relax permissions explicitly when needed.
     */
    umask(077);

    ev_default_fork();

    return;
}

/**
 * Raise file handle limit to reasonable level
 * At some point we should make this a config parameter
 */
/* Returns the file descriptor limit in force afterwards. */
static rlim_t
set_limits(rlim_t max_nofiles) {
    struct rlimit fd_limit = {
        .rlim_cur = max_nofiles,
        .rlim_max = max_nofiles,
    };

    int result = setrlimit(RLIMIT_NOFILE, &fd_limit);
    if (result < 0) {
        warn("Failed to set file handle limit: %s", strerror(errno));

        /* Without privileges the hard limit cannot be raised, but the
         * soft limit can still go up to it */
        if (getrlimit(RLIMIT_NOFILE, &fd_limit) == 0 &&
                fd_limit.rlim_cur < fd_limit.rlim_max &&
                fd_limit.rlim_cur < max_nofiles) {
            fd_limit.rlim_cur = fd_limit.rlim_max < max_nofiles ?
                    fd_limit.rlim_max : max_nofiles;
            /* The limit this leaves is reported below */
            (void)setrlimit(RLIMIT_NOFILE, &fd_limit);
        }
    }

    /* A failure leaves the previous limit, and OpenBSD silently caps it
     * at kern.maxfiles. */
    if (getrlimit(RLIMIT_NOFILE, &fd_limit) < 0 ||
            fd_limit.rlim_cur == RLIM_INFINITY ||
            fd_limit.rlim_cur >= max_nofiles)
        return max_nofiles;

    warn("File handle limit is %llu, lower than the %llu requested",
            (unsigned long long)fd_limit.rlim_cur,
            (unsigned long long)max_nofiles);
    return fd_limit.rlim_cur;
}

/* The uid and gid of the user and group sniproxy runs as */
static void
lookup_user(const char *username, const char *groupname, uid_t *uid,
        gid_t *gid) {
    /* errno only says something when no entry is returned */
    errno = 0;
    struct passwd *user = getpwnam(username);
    if (user == NULL && errno != 0)
        fatal("getpwnam(): %s", strerror(errno));
    else if (user == NULL)
        fatal("getpwnam(): user %s does not exist", username);

    *uid = user->pw_uid;
    *gid = user->pw_gid;

    if (groupname != NULL) {
      errno = 0;
      struct group *group = getgrnam(groupname);
      if (group == NULL && errno != 0)
        fatal("getgrnam(): %s", strerror(errno));
      else if (group == NULL)
        fatal("getgrnam(): group %s does not exist", groupname);

      *gid = group->gr_gid;
    }
}

static void
drop_perms(const char *username, const char *groupname) {
    uid_t uid;
    gid_t gid;

    lookup_user(username, groupname, &uid, &gid);

    /* check if we are already running as the requested user */
    if (getuid() != 0 || geteuid() != 0) {
        if (getuid() != uid || geteuid() != uid)
            fatal("Process UID does not match configured user %s", username);
        if (getgid() != gid || getegid() != gid)
            fatal("Process GID does not match configured gid %lu", (unsigned long)gid);
        /* Still notify logger child so it can tighten sandboxing */
        if (logger_drop_privileges(uid, gid) < 0)
            fatal("logger_drop_privileges(): %s", strerror(errno));
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

    /* Chown log files to the target user so SIGHUP can reopen them */
    logger_chown_files(uid, gid);

    /* drop any supplementary groups */
    if (setgroups(1, &gid) < 0)
        fatal("setgroups(): %s", strerror(errno));

    /* set the main gid */
    if (setgid(gid) < 0)
        fatal("setgid(): %s", strerror(errno));

    /* "source client" needs CAP_NET_RAW for IP_TRANSPARENT once root
     * is gone; keep the capabilities across setuid() and cut them down
     * to that one right after. */
    int keep_net_raw = config_uses_transparent_proxy(config);
    transparent_proxy_capable = keep_net_raw;
    if (keep_net_raw && caps_keep_on_setuid() < 0)
        fatal("keeping CAP_NET_RAW for source client: %s", strerror(errno));

    /* set the main uid - this is irreversible */
    if (setuid(uid) < 0)
        fatal("setuid(): %s", strerror(errno));

    /* verify privileges were actually dropped */
    if (getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0)
        fatal("Failed to drop privileges");
    make_undumpable();

    if (keep_net_raw && caps_limit_to_net_raw() < 0)
        fatal("limiting capabilities to CAP_NET_RAW: %s", strerror(errno));

    /* Now that main process is unprivileged, tell logger child to drop too */
    if (logger_drop_privileges(uid, gid) < 0)
        fatal("logger_drop_privileges(): %s", strerror(errno));
}

static int
config_uses_transparent_proxy(const struct Config *cfg) {
    const struct Listener *listener;

    SLIST_FOREACH(listener, &cfg->listeners, entries)
        if (listener->transparent_proxy)
            return 1;
    return 0;
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
    fprintf(stderr, "Usage: sniproxy [-c <config>] [-f] [-g] [-t] [-n <max file descriptor limit>] [-V] [-T <min TLS version>] [-d]\n");
    fprintf(stderr, "       -g allow group-read (0640) config permissions for SIGHUP reload\n");
    fprintf(stderr, "       -t test configuration and exit\n");
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

    if (configured_fd_limit == 0)
        return 0;

    /* Keep 20% for listeners, resolver, etc., at least 256 descriptors
     * or half of a smaller limit. */
    size_t fd_budget = (size_t)configured_fd_limit;
    size_t headroom = fd_budget / 5;
    size_t min_headroom = fd_budget / 2 < 256 ? fd_budget / 2 : 256;
    if (headroom < min_headroom)
        headroom = min_headroom;

    /* A proxied connection holds two descriptors: the client socket and
     * the backend one. */
    size_t ceiling = (fd_budget - headroom) / 2;
    return ceiling > 0 ? ceiling : 1;
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

/* Create the pidfile with O_EXCL and write our pid into it. Returns 0 when
 * this process created the file (the caller should then arrange removal at
 * exit), or -1 when no pidfile was created by this call (e.g. it already
 * existed). Post-creation validation failures still return 0: we own the
 * freshly created file and want it cleaned up. */
static int
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
        if (errno == EEXIST)
            err("PID file %s already exists (possible race or stale file)", path);
        else
            err("open PID file %s: %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        err("fstat PID file: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* Validate file type and attributes for security */
    if (!S_ISREG(st.st_mode)) {
        err("PID file is not a regular file");
        close(fd);
        return 0;
    }

    /* Defense-in-depth: verify file was just created and we own it */
    if (st.st_nlink != 1) {
        err("PID file has unexpected link count: %lu",
                (unsigned long)st.st_nlink);
        close(fd);
        return 0;
    }

    if (st.st_uid != getuid()) {
        err("PID file owned by unexpected UID: %u (expected %u)",
                (unsigned int)st.st_uid, (unsigned int)getuid());
        close(fd);
        return 0;
    }

    if (st.st_size != 0) {
        err("PID file has unexpected size: %lld",
                (long long)st.st_size);
        close(fd);
        return 0;
    }

    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (fchmod(fd, st.st_mode & ~(S_IWGRP | S_IWOTH)) != 0)
            warn("fchmod PID file: %s", strerror(errno));
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        err("fdopen PID file: %s", strerror(errno));
        goto cleanup;
    }

    if (fprintf(fp, "%d\n", pid) < 0 || fflush(fp) != 0)
        err("write PID file %s: %s", path, strerror(errno));

cleanup:
    if (fp != NULL)
        fclose(fp);
    else if (fd >= 0)
        close(fd);

    return 0;
}

static void
early_signal_cb(int signum) {
    if (signum == SIGHUP)
        early_sighup = 1;
    else
        early_sigusr1 = 1;
}

static void
signal_cb(struct ev_loop *loop, struct ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGHUP:
                reopen_loggers();
                reload_config(config, loop);
                if (!transparent_proxy_capable &&
                        config_uses_transparent_proxy(config))
                    warn("source client needs a restart: CAP_NET_RAW "
                            "was given up when privileges were dropped");
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

static void
sigchld_cb(struct ev_loop *loop __attribute__((unused)),
        struct ev_signal *w __attribute__((unused)),
        int revents __attribute__((unused))) {
    /* Reap zombie children promptly.  Subsystem-specific waitpid() calls
     * in logger, resolver, and binder already handle ECHILD gracefully. */
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}
