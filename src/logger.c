/*
 * Copyright (c) 2013, Dustin Lundquist <dustin@null-ptr.net>
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
#include "config.h"
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "sniproxy"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <limits.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <grp.h>
#include <ev.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#ifdef HAVE_BSD_UNISTD_H
#include <bsd/unistd.h>
#endif
#include "logger.h"
#include "fd_util.h"
#include "ipc_crypto.h"
#include "seccomp_filter.h"

struct Logger {
    struct LogSink *sink;
    int priority;
    int facility;
    int reference_count;
};

struct LogSink {
    enum {
        LOG_SINK_SYSLOG,
        LOG_SINK_STDERR,
        LOG_SINK_FILE
    } type;
    const char *filepath;

    FILE *fd;
    int fd_owned;
    uint32_t id;
    int reference_count;
    SLIST_ENTRY(LogSink) entries;
};

struct ChildSink {
    uint32_t id;
    int type;
    FILE *file;
    char *filepath;
    SLIST_ENTRY(ChildSink) entries;
};

SLIST_HEAD(ChildSink_head, ChildSink);

#if defined(__linux__) && !defined(HAVE_SETPROCTITLE)
extern char **environ;

static char **logger_title_argv = NULL;
static int logger_title_argc = 0;
static char *logger_title_buf = NULL;
static size_t logger_title_buf_len = 0;

static int
logger_copy_environment(void) {
    size_t env_count = 0;
    while (environ != NULL && environ[env_count] != NULL)
        env_count++;

    if (env_count == 0)
        return 1;

    char **new_environ = calloc(env_count + 1, sizeof(char *));
    if (new_environ == NULL)
        return 0;

    for (size_t i = 0; i < env_count; i++) {
        new_environ[i] = strdup(environ[i]);
        if (new_environ[i] == NULL) {
            for (size_t j = 0; j < i; j++)
                free(new_environ[j]);
            free(new_environ);
            return 0;
        }
    }
    new_environ[env_count] = NULL;

    environ = new_environ;

    return 1;
}

static void
logger_set_process_title_fallback(const char *title) {
    if (logger_title_buf == NULL || logger_title_buf_len == 0)
        return;

    size_t len = strnlen(title, logger_title_buf_len - 1);
    memset(logger_title_buf, '\0', logger_title_buf_len);
    memcpy(logger_title_buf, title, len);

    if (logger_title_argv != NULL && logger_title_argc > 0) {
        logger_title_argv[0] = logger_title_buf;
        for (int i = 1; i < logger_title_argc; i++)
            logger_title_argv[i] = NULL;
    }
}
#endif

#if defined(__linux__) && !defined(HAVE_SETPROCTITLE)
void
logger_prepare_process_title(int argc, char **argv) {
    if (argc <= 0 || argv == NULL || argv[0] == NULL)
        return;

    logger_title_argv = argv;
    logger_title_argc = argc;

    char *start = argv[0];
    char *end = start + strlen(start);

    for (int i = 1; i < argc && argv[i] != NULL; i++) {
        char *candidate = argv[i] + strlen(argv[i]);
        if (candidate > end)
            end = candidate;
    }

    if (environ != NULL) {
        for (char **env = environ; *env != NULL; env++) {
            char *candidate = *env + strlen(*env);
            if (candidate > end)
                end = candidate;
        }
    }

    logger_title_buf = start;
    if (end > start)
        logger_title_buf_len = (size_t)(end - start);
    else
        logger_title_buf_len = strlen(start);

    if (!logger_copy_environment()) {
        logger_title_buf = NULL;
        logger_title_buf_len = 0;
        logger_title_argv = NULL;
        logger_title_argc = 0;
    }
}
#else
void
logger_prepare_process_title(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
}
#endif

static struct Logger *default_logger = NULL;
static SLIST_HEAD(LogSink_head, LogSink) sinks = SLIST_HEAD_INITIALIZER(sinks);

static pid_t logger_pid = -1;
static int logger_sock = -1;
static struct ipc_crypto_state logger_crypto_parent;
static struct ipc_crypto_state logger_crypto_child;
static uint32_t next_sink_id = 1;
static int logger_process_enabled = 0;
static int logger_process_failed = 0;
static int logger_parent_fs_locked = 0;

/* Health check state */
#define LOGGER_HEALTH_CHECK_INTERVAL 30.0
#define LOGGER_HEALTH_CHECK_TIMEOUT 5.0
static struct ev_timer logger_health_timer;
static struct ev_loop *logger_health_loop = NULL;
static uint32_t logger_ping_id = 0;
static int logger_ping_pending = 0;
static int logger_health_check_active = 0;

struct logger_ipc_header;

static void free_logger(struct Logger *);
static void init_default_logger(void);
static void vlog_msg(struct Logger *, int, const char *, va_list);
static int logger_requires_payload(const struct Logger *);
static size_t format_log_payload(char *, size_t, const char *, va_list, int);
static void free_at_exit(void);
static int lookup_syslog_facility(const char *);
static size_t timestamp(char *, size_t);
static struct LogSink *obtain_stderr_sink(void);
static struct LogSink *obtain_syslog_sink(void);
static struct LogSink *obtain_file_sink(const char *);
static struct LogSink *log_sink_ref_get(struct LogSink *);
static void log_sink_ref_put(struct LogSink *);
static void free_sink(struct LogSink *);
static int ensure_logger_process(void);
static void logger_process_shutdown(void);
static void disable_logger_process(void);
static void logger_child_main(int) __attribute__((noreturn));
static int send_logger_message(const struct logger_ipc_header *, const void *,
        size_t, int);
static int send_logger_new_sink(struct LogSink *, int fd_to_send);
static int send_logger_log(struct Logger *, int, const char *, size_t);
static int send_logger_reopen(struct LogSink *, int fd_to_send);
static int send_logger_drop(struct LogSink *);
static int send_logger_privileges(uid_t, gid_t);
static int logger_send_privileges(uid_t uid, gid_t gid);
static void logger_child_handle_message(int, struct logger_ipc_header *, int, char *);
static struct ChildSink *child_sink_lookup(struct ChildSink_head *, uint32_t);
static void child_sink_free(struct ChildSink_head *, struct ChildSink *);
static FILE *logger_child_open_file(const char *filepath);
static int logger_register_sink(struct LogSink *sink);
static void logger_resend_sinks(void);
static void logger_health_check_cb(struct ev_loop *, struct ev_timer *, int);
static int logger_send_ping(void);
static int logger_check_pong(void);

static void __attribute__((noreturn))
logger_child_exit(int status) {
    ipc_crypto_state_clear(&logger_crypto_child);
    _exit(status);
}

#define LOGGER_CMD_NEW_SINK       1U
#define LOGGER_CMD_LOG            2U
#define LOGGER_CMD_REOPEN         3U
#define LOGGER_CMD_DROP           4U
#define LOGGER_CMD_SHUTDOWN       5U
#define LOGGER_CMD_PRIVILEGES     6U
#define LOGGER_CMD_PING           7U
#define LOGGER_CMD_PONG           8U

#define LOGGER_IPC_CHANNEL_ID 0x4c4f4752u /* LOGR */
#define LOGGER_IPC_MAX_PAYLOAD (64 * 1024)

struct logger_privileges_payload {
    uint32_t uid;
    uint32_t gid;
};

struct logger_ipc_header {
    uint32_t type;
    uint32_t sink_id;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t payload_len;
};

static int logger_process_initialized = 0;
static struct ChildSink_head child_sink_head = SLIST_HEAD_INITIALIZER(child_sink_head);

struct Logger *
new_syslog_logger(const char *facility) {
    if (!ensure_logger_process())
        logger_process_enabled = 0;

    struct Logger *logger = calloc(1, sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_syslog_sink();
        if (logger->sink == NULL) {
            free(logger);
            return NULL;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = lookup_syslog_facility(facility);
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    return logger;
}

struct Logger *
new_file_logger(const char *filepath) {
    if (!ensure_logger_process())
        logger_process_enabled = 0;

    struct Logger *logger = calloc(1, sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_file_sink(filepath);
        if (logger->sink == NULL) {
            free(logger);
            return NULL;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = 0;
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    return logger;
}

/* Open a log file defensively and verify the fd still refers to the on-disk path.
 * This limits TOCTOU exposure between open() and validation by rejecting
 * mismatched inode/device pairs or non-regular files. */
static FILE *
open_log_file_checked(const char *filepath) {
    int open_flags = O_WRONLY | O_APPEND | O_CREAT;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif

    int fd = open(filepath, open_flags, 0600);
    if (fd < 0)
        return NULL;

    struct stat st_fd;
    if (fstat(fd, &st_fd) != 0 || !S_ISREG(st_fd.st_mode)) {
        int saved_errno = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    /* Ensure the path we opened still refers to the same inode to block
     * post-open symlink/hardlink swaps. */
    struct stat st_path;
    if (lstat(filepath, &st_path) != 0 ||
            !S_ISREG(st_path.st_mode) ||
            st_fd.st_dev != st_path.st_dev ||
            st_fd.st_ino != st_path.st_ino) {
        int saved_errno = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    FILE *file = fdopen(fd, "a");
    if (file == NULL) {
        int saved_errno = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    setvbuf(file, NULL, _IOLBF, 0);

    return file;
}

void
reopen_loggers(void) {
    struct LogSink *sink;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_SYSLOG) {
            if (logger_process_enabled) {
                if (send_logger_reopen(sink, -1) < 0) {
                    err("failed to reopen syslog sink: %s", strerror(errno));
                    disable_logger_process();
                }
            } else {
                closelog();
                openlog(PACKAGE_NAME, LOG_PID, 0);
            }
        } else if (sink->type == LOG_SINK_FILE) {
            if (logger_process_enabled) {
                if (send_logger_reopen(sink, -1) < 0) {
                    err("failed to request reopen for log file %s: %s",
                            sink->filepath, strerror(errno));
                    disable_logger_process();
                }
                if (!logger_parent_fs_locked && sink->fd != NULL && sink->fd_owned) {
                    FILE *file = open_log_file_checked(sink->filepath);
                    if (file == NULL) {
                        err("failed to reopen local log file %s: %s",
                                sink->filepath, strerror(errno));
                        fclose(sink->fd);
                        sink->fd = NULL;
                        sink->fd_owned = 0;
                    } else {
                        fclose(sink->fd);
                        sink->fd = file;
                        sink->fd_owned = 1;
                    }
                }
            } else {
                if (!logger_parent_fs_locked) {
                    FILE *file = open_log_file_checked(sink->filepath);
                    if (file == NULL) {
                        err("failed to reopen log file %s: %s",
                                sink->filepath, strerror(errno));
                        if (sink->fd != NULL)
                            fclose(sink->fd);
                        sink->fd = NULL;
                    } else {
                        if (sink->fd != NULL)
                            fclose(sink->fd);
                        sink->fd = file;
                        sink->fd_owned = 1;
                    }
                } else if (sink->fd == NULL) {
                    sink->fd = stderr;
                    sink->fd_owned = 0;
                }
            }
        }
        sink = SLIST_NEXT(sink, entries);
    }
}

void
logger_for_each_file_sink(void (*callback)(const char *, void *), void *userdata) {
    struct LogSink *sink;

    if (callback == NULL)
        return;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_FILE && sink->filepath != NULL)
            callback(sink->filepath, userdata);
        sink = SLIST_NEXT(sink, entries);
    }
}

void
logger_chown_files(uid_t uid, gid_t gid) {
    struct LogSink *sink;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_FILE && sink->fd != NULL && sink->fd_owned) {
            int fd = fileno(sink->fd);
            if (fd >= 0 && fchown(fd, uid, gid) < 0)
                warn("Failed to chown log file %s: %s",
                        sink->filepath, strerror(errno));
        }
        sink = SLIST_NEXT(sink, entries);
    }
}

int
logger_drop_privileges(uid_t uid, gid_t gid) {
    if (!logger_process_enabled)
        return 0;

    return logger_send_privileges(uid, gid);
}

void
set_default_logger(struct Logger *new_logger) {
    struct Logger *old_default_logger = default_logger;

    if (new_logger == NULL)
        return;
    default_logger = logger_ref_get(new_logger);
    logger_ref_put(old_default_logger);
}

void
set_logger_priority(struct Logger *logger, int priority) {
    if (logger == NULL)
        return;
    if (priority < LOG_EMERG || priority > LOG_DEBUG)
        return;
    logger->priority = priority;
}

void
logger_ref_put(struct Logger *logger) {
    if (logger == NULL)
        return;

    if (logger->reference_count <= 0)
        return;
    logger->reference_count--;
    if (logger->reference_count == 0)
        free_logger(logger);
}

struct Logger *
logger_ref_get(struct Logger *logger) {
    if (logger == NULL)
        return NULL;

    if (logger->reference_count == INT_MAX) {
        err("%s: reference_count overflow", __func__);
        return logger;
    }
    logger->reference_count++;

    return logger;
}

static void
free_logger(struct Logger *logger) {
    if (logger == NULL)
        return;

    log_sink_ref_put(logger->sink);
    logger->sink = NULL;

    free(logger);
}

void
log_msg(struct Logger *logger, int priority, const char *format, ...) {
    va_list args;

    va_start(args, format);
    vlog_msg(logger, priority, format, args);
    va_end(args);
}

void
fatal(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_CRIT, format, args);
    va_end(args);

    logger_process_shutdown();

    exit(EXIT_FAILURE);
}

void
err(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_ERR, format, args);
    va_end(args);
}

void
warn(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_WARNING, format, args);
    va_end(args);
}

void
notice(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_NOTICE, format, args);
    va_end(args);
}

void
info(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_INFO, format, args);
    va_end(args);
}

void
debug(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_DEBUG, format, args);
    va_end(args);
}

static void
vlog_msg(struct Logger *logger, int priority, const char *format, va_list args) {
    if (logger == NULL)
        return;

    if (priority > logger->priority)
        return;

    char buffer[1024];
    size_t payload_len = 0;
    int have_payload = 0;
    const int need_payload = logger_requires_payload(logger);

    if (need_payload) {
        va_list args_copy;
        va_copy(args_copy, args);
        int with_timestamp = (logger->sink == NULL ||
                logger->sink->type != LOG_SINK_SYSLOG);
        payload_len = format_log_payload(buffer, sizeof(buffer), format,
                args_copy, with_timestamp);
        va_end(args_copy);
        if (payload_len > 0)
            have_payload = 1;
    }

    if (logger_process_enabled && logger->sink != NULL && have_payload &&
            logger->sink->type != LOG_SINK_STDERR) {
        if (send_logger_log(logger, priority, buffer, payload_len) == 0)
            return;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer temporarily full under heavy logging.
             * Drop this message rather than permanently killing the
             * logger child process. */
            return;
        }

        disable_logger_process();
    }

    if (logger->sink == NULL)
        return;

    if (logger->sink->type == LOG_SINK_SYSLOG) {
        vsyslog(logger->facility | priority, format, args);
    } else if (logger->sink->fd != NULL && have_payload) {
        (void)fwrite(buffer, 1, payload_len, logger->sink->fd);
    }
}

static void
init_default_logger(void) {
    static int initializing = 0;
    struct Logger *logger = NULL;

    if (default_logger != NULL)
        return;

    if (initializing)
        return;

    initializing = 1;

    if (!ensure_logger_process())
        logger_process_enabled = 0;

    logger = calloc(1, sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_stderr_sink();
        if (logger->sink == NULL) {
            free(logger);
            initializing = 0;
            return;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = 0;
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    if (logger == NULL) {
        initializing = 0;
        return;
    }

    if (!logger_process_initialized) {
        atexit(free_at_exit);
        logger_process_initialized = 1;
    }

    default_logger = logger_ref_get(logger);
    initializing = 0;
}

static void
free_at_exit(void) {
    logger_ref_put(default_logger);
    default_logger = NULL;
    logger_process_shutdown();
}

static int
lookup_syslog_facility(const char *facility) {
    static const struct {
        const char *name;
        int number;
    } facilities[] = {
        { "auth",   LOG_AUTH },
        { "cron",   LOG_CRON },
        { "daemon", LOG_DAEMON },
        { "ftp",    LOG_FTP },
        { "local0", LOG_LOCAL0 },
        { "local1", LOG_LOCAL1 },
        { "local2", LOG_LOCAL2 },
        { "local3", LOG_LOCAL3 },
        { "local4", LOG_LOCAL4 },
        { "local5", LOG_LOCAL5 },
        { "local6", LOG_LOCAL6 },
        { "local7", LOG_LOCAL7 },
        { "mail",   LOG_MAIL },
        { "news",   LOG_NEWS },
        { "user",   LOG_USER },
        { "uucp",   LOG_UUCP },
    };

    if (facility == NULL || *facility == '\0')
        return LOG_USER;

    for (size_t i = 0; i < sizeof(facilities) / sizeof(facilities[0]); i++)
        if (strcasecmp(facilities[i].name, facility) == 0)
            return facilities[i].number;

    /* fall back value */
    return LOG_USER;
}

static struct LogSink *
obtain_stderr_sink(void) {
    struct LogSink *sink;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_STDERR)
            return sink;
        sink = SLIST_NEXT(sink, entries);
    }

    sink = calloc(1, sizeof(struct LogSink));
    if (sink != NULL) {
        sink->type = LOG_SINK_STDERR;
        sink->filepath = NULL;
        sink->fd = stderr;
        sink->fd_owned = 0;
        sink->id = next_sink_id++;
        sink->reference_count = 0;

        SLIST_INSERT_HEAD(&sinks, sink, entries);

        if (logger_process_enabled) {
            if (send_logger_new_sink(sink, -1) < 0) {
                /* Use fprintf instead of err() to avoid recursion:
                 * err() -> init_default_logger() -> obtain_stderr_sink()
                 * and default_logger is not yet set at this point */
                fprintf(stderr, "failed to register stderr sink with "
                        "logger process: %s\n", strerror(errno));
                disable_logger_process();
            }
        }
    }

    return sink;
}

static struct LogSink *
obtain_syslog_sink(void) {
    struct LogSink *sink;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_SYSLOG)
            return sink;
        sink = SLIST_NEXT(sink, entries);
    }

    sink = calloc(1, sizeof(struct LogSink));
    if (sink != NULL) {
        sink->type = LOG_SINK_SYSLOG;
        sink->filepath = NULL;
        sink->fd = NULL;
        sink->fd_owned = 0;
        sink->id = next_sink_id++;
        sink->reference_count = 0;

        if (!logger_process_enabled)
            openlog(PACKAGE_NAME, LOG_PID, 0);

        SLIST_INSERT_HEAD(&sinks, sink, entries);

        if (logger_process_enabled) {
            if (send_logger_new_sink(sink, -1) < 0) {
                err("failed to register syslog sink with logger process: %s",
                        strerror(errno));
                disable_logger_process();
            }
        }
    }

    return sink;
}

static struct LogSink *
obtain_file_sink(const char *filepath) {
    struct LogSink *sink;

    if (filepath == NULL)
        return NULL;

    sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_FILE &&
                strcmp(sink->filepath, filepath) == 0)
            return sink;
        sink = SLIST_NEXT(sink, entries);
    }

    sink = calloc(1, sizeof(struct LogSink));
    if (sink == NULL)
        return NULL;

    sink->type = LOG_SINK_FILE;
    sink->filepath = strdup(filepath);
    if (sink->filepath == NULL) {
        int saved_errno = errno;
        free(sink);
        errno = saved_errno;
        err("Failed to duplicate log file path: %s", filepath);
        return NULL;
    }
    sink->reference_count = 0;
    sink->id = next_sink_id++;
    sink->fd = NULL;
    sink->fd_owned = 0;

    int fd_for_child = -1;

    if (!logger_process_enabled || !logger_parent_fs_locked) {
        int open_flags = O_WRONLY | O_APPEND | O_CREAT;
#ifdef O_CLOEXEC
        open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        open_flags |= O_NOFOLLOW;
#endif

        int fd = open(filepath, open_flags, 0600);
        if (fd < 0) {
            int saved_errno = errno;
            free((char *)sink->filepath);
            free(sink);
            errno = saved_errno;
            err("Failed to open new log file %s: %s", filepath, strerror(saved_errno));
            return NULL;
        }

        struct stat st;
        if (fstat(fd, &st) != 0) {
            int saved_errno = errno;
            close(fd);
            free((char *)sink->filepath);
            free(sink);
            errno = saved_errno;
            err("Failed to stat log file: %s", filepath);
            return NULL;
        }

        if (!S_ISREG(st.st_mode)) {
            close(fd);
            free((char *)sink->filepath);
            free(sink);
            err("Refusing to write to non-regular log file: %s", filepath);
            errno = EINVAL;
            return NULL;
        }

        if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            if (fchmod(fd, st.st_mode & ~(S_IWGRP | S_IWOTH)) != 0) {
                warn("Failed to drop group/world write permission on log file %s: %s",
                        filepath, strerror(errno));
            }
        }

        FILE *file = fdopen(fd, "a");
        if (file == NULL) {
            int saved_errno = errno;
            close(fd);
            free((char *)sink->filepath);
            free(sink);
            errno = saved_errno;
            err("Failed to associate stream with log file: %s", filepath);
            return NULL;
        }

        setvbuf(file, NULL, _IOLBF, 0);
        sink->fd = file;
        sink->fd_owned = 1;

        if (logger_process_enabled) {
            fd_for_child = dup(fileno(file));
            if (fd_for_child < 0) {
                int saved_errno = errno;
                fclose(file);
                sink->fd = NULL;
                sink->fd_owned = 0;
                free((char *)sink->filepath);
                free(sink);
                errno = saved_errno;
                err("Failed to duplicate log file descriptor: %s", filepath);
                return NULL;
            }

            if (set_cloexec(fd_for_child) < 0) {
                int saved_errno = errno;
                close(fd_for_child);
                fclose(file);
                sink->fd = NULL;
                sink->fd_owned = 0;
                free((char *)sink->filepath);
                free(sink);
                errno = saved_errno;
                err("Failed to mark log file descriptor close-on-exec: %s", filepath);
                return NULL;
            }
        }
    }

    if (logger_process_enabled) {
        /* send_logger_new_sink always closes fd_for_child */
        if (send_logger_new_sink(sink, fd_for_child) < 0) {
            err("Failed to register log file %s with logger process: %s", filepath,
                    strerror(errno));
            /* Fall back to in-process logging */
            disable_logger_process();
        }
    } else if (fd_for_child >= 0) {
        close(fd_for_child);
    }

    if (!logger_process_enabled && sink->fd == NULL) {
        if (!logger_parent_fs_locked) {
            FILE *file = open_log_file_checked(filepath);
            if (file == NULL) {
                int saved_errno = errno;
                free((char *)sink->filepath);
                free(sink);
                errno = saved_errno;
                err("Failed to open new log file %s: %s", filepath,
                        strerror(saved_errno));
                return NULL;
            }
            sink->fd = file;
            sink->fd_owned = 1;
        } else {
            sink->fd = stderr;
            sink->fd_owned = 0;
        }
    }

    SLIST_INSERT_HEAD(&sinks, sink, entries);

    return sink;
}

static struct LogSink *
log_sink_ref_get(struct LogSink *sink) {
    if (sink == NULL)
        return NULL;

    if (sink->reference_count == INT_MAX) {
        err("%s: reference_count overflow", __func__);
        return sink;
    }
    sink->reference_count++;

    return sink;
}

static void
log_sink_ref_put(struct LogSink *sink) {
    if (sink == NULL)
        return;

    if (sink->reference_count <= 0)
        return;
    sink->reference_count--;
    if (sink->reference_count == 0)
        free_sink(sink);
}

static void
free_sink(struct LogSink *sink) {
    if (sink == NULL)
        return;

    SLIST_REMOVE(&sinks, sink, LogSink, entries);

    if (logger_process_enabled) {
        if (send_logger_drop(sink) < 0)
            disable_logger_process();
    }

    switch(sink->type) {
        case LOG_SINK_SYSLOG:
            if (!logger_process_enabled)
                closelog();
            break;
        case LOG_SINK_STDERR:
            sink->fd = NULL;
            break;
        case LOG_SINK_FILE:
            if (sink->fd != NULL && sink->fd_owned)
                fclose(sink->fd);
            sink->fd = NULL;
            sink->fd_owned = 0;
            free((char *)sink->filepath);
            sink->filepath = NULL;
            break;
        default:
            err("unknown log sink type: %d", sink->type);
            break;
    }

    free(sink);
}

static int
logger_requires_payload(const struct Logger *logger) {
    if (logger_process_enabled)
        return 1;
    if (logger == NULL || logger->sink == NULL)
        return 0;

    return logger->sink->type != LOG_SINK_SYSLOG;
}

static size_t
format_log_payload(char *buffer, size_t buffer_len, const char *format,
        va_list args, int with_timestamp) {
    if (buffer == NULL || buffer_len < 3)
        return 0;

    size_t len = with_timestamp ? timestamp(buffer, buffer_len) : 0;
    size_t remaining = buffer_len > len ? buffer_len - len : 0;

    int written = vsnprintf(buffer + len, remaining, format, args);
    if (written < 0)
        return 0;

    size_t total = len + (size_t)written;
    if (total >= buffer_len)
        total = buffer_len - 1;
    if (total + 2 >= buffer_len)
        total = buffer_len - 2;
    buffer[total++] = '\n';
    buffer[total] = '\0';

    return total;
}

static size_t
timestamp(char *dst, size_t dst_len) {
    /* Uses time() because the ev_loop is not available in the
     * logger formatting path without a significant refactor. */
    time_t now = time(NULL);
    static struct {
        time_t when;
        char string[32];
        size_t len;
    } timestamp_cache = { .when = 0, .string = {'\0'}, .len = 0 };

    if (now != timestamp_cache.when) {
#ifdef RFC3339_TIMESTAMP
        struct tm *tmp = gmtime(&now);
#else
        struct tm *tmp = localtime(&now);
#endif
        if (tmp == NULL) {
            timestamp_cache.len = 0;
            timestamp_cache.string[0] = '\0';
        } else {
#ifdef RFC3339_TIMESTAMP
            timestamp_cache.len = strftime(timestamp_cache.string,
                    sizeof(timestamp_cache.string), "%FT%TZ ", tmp);
#else
            timestamp_cache.len = strftime(timestamp_cache.string,
                    sizeof(timestamp_cache.string), "%F %T ", tmp);
#endif
        }

        timestamp_cache.when = now;
    }

    if (dst == NULL)
        return timestamp_cache.len;

    if (dst_len == 0)
        return 0;

    size_t copy_len = timestamp_cache.len;
    if (copy_len > sizeof(timestamp_cache.string) - 1)
        copy_len = sizeof(timestamp_cache.string) - 1;

    if (copy_len >= dst_len)
        copy_len = dst_len - 1;

    memcpy(dst, timestamp_cache.string, copy_len);
    dst[copy_len] = '\0';

    return copy_len;
}

static void
disable_logger_process(void) {
    if (!logger_process_enabled && logger_sock < 0) {
        logger_process_failed = 1;
        return;
    }

    if (logger_sock >= 0) {
        close(logger_sock);
        logger_sock = -1;
    }

    if (logger_pid > 0) {
        /* Use WNOHANG to avoid blocking the mainloop if the child
         * is stuck on filesystem I/O (e.g. hung NFS mount) */
        int wr = waitpid(logger_pid, NULL, WNOHANG);
        if (wr == 0) {
            kill(logger_pid, SIGKILL);
            waitpid(logger_pid, NULL, 0);
        } else if (wr == -1 && errno == ECHILD) {
            /* Not our child (reparented after daemonize) */
            kill(logger_pid, SIGKILL);
        }
        logger_pid = -1;
    }

    logger_process_enabled = 0;
    logger_process_failed = 1;

    struct LogSink *sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_FILE && sink->fd == NULL && sink->filepath != NULL) {
            if (!logger_parent_fs_locked) {
                sink->fd = open_log_file_checked(sink->filepath);
                if (sink->fd != NULL)
                    sink->fd_owned = 1;
            } else {
                sink->fd = stderr;
                sink->fd_owned = 0;
            }
        } else if (sink->type == LOG_SINK_SYSLOG) {
            openlog(PACKAGE_NAME, LOG_PID, 0);
        } else if (sink->type == LOG_SINK_STDERR) {
            sink->fd = stderr;
        }
        sink = SLIST_NEXT(sink, entries);
    }

    ipc_crypto_state_clear(&logger_crypto_parent);
}

static int
ensure_logger_process(void) {
    if (logger_process_enabled || logger_process_failed)
        return logger_process_enabled;

    int sockets[2];
    int socket_type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif

    if (socketpair(AF_UNIX, socket_type, 0, sockets) < 0) {
        logger_process_failed = 1;
        return 0;
    }

    if (set_cloexec(sockets[0]) < 0 || set_cloexec(sockets[1]) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        logger_process_failed = 1;
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sockets[0]);
        close(sockets[1]);
        logger_process_failed = 1;
        return 0;
    } else if (pid == 0) {
        close(sockets[0]);
        int child_fd = fd_preserve_only(sockets[1]);
        if (child_fd < 0) {
            _exit(EXIT_FAILURE);
        }
        /* Redirect stderr to /dev/null so that fprintf(stderr) in error
         * paths does not accidentally write to a log file fd that reuses
         * fd 2 after sink files are opened. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            if (devnull != STDERR_FILENO) {
                (void)dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        logger_child_main(child_fd);
    }

    close(sockets[1]);
    logger_sock = sockets[0];
    logger_pid = pid;

    /* Set non-blocking to prevent mainloop stall under heavy logging */
    int flags = fcntl(logger_sock, F_GETFL);
    if (flags >= 0)
        fcntl(logger_sock, F_SETFL, flags | O_NONBLOCK);

    if (ipc_crypto_channel_init(&logger_crypto_parent, LOGGER_IPC_CHANNEL_ID,
                IPC_CRYPTO_ROLE_PARENT) < 0) {
        /* Use fprintf instead of err() to avoid recursion:
         * err() -> init_default_logger() -> ensure_logger_process() */
        fprintf(stderr, "Failed to initialize logger IPC crypto\n");
        disable_logger_process();
        return 0;
    }
    logger_process_enabled = 1;
    logger_resend_sinks();

    return 1;
}

static void
logger_process_shutdown(void) {
    if (!logger_process_enabled)
        return;

    struct logger_ipc_header header = {
        .type = LOGGER_CMD_SHUTDOWN,
        .sink_id = 0,
        .arg0 = 0,
        .arg1 = 0,
        .payload_len = 0,
    };

    if (logger_sock >= 0) {
        send_logger_message(&header, NULL, 0, -1);
        close(logger_sock);
        logger_sock = -1;
    }

    if (logger_pid > 0) {
        /* Use WNOHANG to avoid blocking if the child is stuck on
         * filesystem I/O; SIGKILL ensures it terminates */
        int wr = waitpid(logger_pid, NULL, WNOHANG);
        if (wr == 0) {
            kill(logger_pid, SIGKILL);
            waitpid(logger_pid, NULL, 0);
        } else if (wr == -1 && errno == ECHILD) {
            /* Not our child (reparented after daemonize) */
            kill(logger_pid, SIGKILL);
        }
    }

    logger_pid = -1;
    logger_process_enabled = 0;
    ipc_crypto_state_clear(&logger_crypto_parent);
}

static int
send_logger_message(const struct logger_ipc_header *header,
        const void *payload, size_t payload_len, int fd_to_send) {
    if (logger_sock < 0)
        return -1;

    size_t total = sizeof(*header) + payload_len;
    uint8_t stack_buf[sizeof(*header) + 1024];
    uint8_t *buf;

    if (total <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        buf = malloc(total);
        if (buf == NULL)
            return -1;
    }

    memcpy(buf, header, sizeof(*header));
    if (payload_len > 0 && payload != NULL)
        memcpy(buf + sizeof(*header), payload, payload_len);

    int rc = ipc_crypto_send_msg(&logger_crypto_parent, logger_sock,
            buf, total, fd_to_send);

    if (buf != stack_buf)
        free(buf);

    return rc;
}

static int
send_logger_new_sink(struct LogSink *sink, int fd_to_send) {
    struct logger_ipc_header header = {
        .type = LOGGER_CMD_NEW_SINK,
        .sink_id = sink->id,
        .arg0 = (uint32_t)sink->type,
        .arg1 = 0,
        .payload_len = 0,
    };

    const char *payload = NULL;
    if (sink->type == LOG_SINK_FILE && sink->filepath != NULL)
        payload = sink->filepath;

    if (payload != NULL)
        header.payload_len = (uint32_t)(strlen(payload) + 1);

    int rc = send_logger_message(&header, payload, header.payload_len,
            fd_to_send);

    if (fd_to_send >= 0)
        close(fd_to_send);

    return rc;
}

static int
send_logger_log(struct Logger *logger, int priority, const char *message,
        size_t len) {
    if (logger == NULL || logger->sink == NULL)
        return -1;

    struct logger_ipc_header header = {
        .type = LOGGER_CMD_LOG,
        .sink_id = logger->sink->id,
        .arg0 = (uint32_t)priority,
        .arg1 = (uint32_t)logger->facility,
        .payload_len = (uint32_t)(len + 1),
    };

    return send_logger_message(&header, message, header.payload_len, -1);
}

static int
send_logger_reopen(struct LogSink *sink, int fd_to_send) {
    struct logger_ipc_header header = {
        .type = LOGGER_CMD_REOPEN,
        .sink_id = sink->id,
        .arg0 = (uint32_t)sink->type,
        .arg1 = 0,
        .payload_len = 0,
    };

    int rc = send_logger_message(&header, NULL, 0, fd_to_send);

    if (fd_to_send >= 0)
        close(fd_to_send);

    return rc;
}

static int
send_logger_drop(struct LogSink *sink) {
    struct logger_ipc_header header = {
        .type = LOGGER_CMD_DROP,
        .sink_id = sink->id,
        .arg0 = 0,
        .arg1 = 0,
        .payload_len = 0,
    };

    return send_logger_message(&header, NULL, 0, -1);
}

static int
send_logger_privileges(uid_t uid, gid_t gid) {
    if (uid > UINT32_MAX || gid > UINT32_MAX) {
        errno = EOVERFLOW;
        return -1;
    }

    struct logger_privileges_payload payload = {
        .uid = (uint32_t)uid,
        .gid = (uint32_t)gid,
    };

    struct logger_ipc_header header = {
        .type = LOGGER_CMD_PRIVILEGES,
        .sink_id = 0,
        .arg0 = 0,
        .arg1 = 0,
        .payload_len = sizeof(payload),
    };

    return send_logger_message(&header, &payload, sizeof(payload), -1);
}

static int
logger_send_privileges(uid_t uid, gid_t gid) {
    if (!logger_process_enabled)
        return 0;

    int attempt = 0;
    while (attempt < 2) {
        if (send_logger_privileges(uid, gid) == 0)
            return 0;

        int saved_errno = errno;
        if (saved_errno != EPIPE && saved_errno != ECONNRESET) {
            errno = saved_errno;
            return -1;
        }

        disable_logger_process();
        logger_process_failed = 0;
        if (!ensure_logger_process()) {
            errno = saved_errno;
            return -1;
        }
        attempt++;
    }

    errno = EIO;
    return -1;
}

static int
recv_logger_message(int fd, struct logger_ipc_header *header,
        char **payload, int *received_fd) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int rc = ipc_crypto_recv_msg(&logger_crypto_child, fd,
            sizeof(*header) + LOGGER_IPC_MAX_PAYLOAD,
            &plain, &plain_len, received_fd);
    if (rc <= 0)
        return rc;

    if (plain_len < sizeof(*header)) {
        free(plain);
        goto fail_close_fd;
    }

    memcpy(header, plain, sizeof(*header));

    size_t data_len = plain_len - sizeof(*header);
    if (data_len != header->payload_len) {
        free(plain);
        goto fail_close_fd;
    }

    if (data_len > 0) {
        *payload = malloc(data_len);
        if (*payload == NULL) {
            free(plain);
            goto fail_close_fd;
        }
        memcpy(*payload, plain + sizeof(*header), data_len);

        if (header->type == LOGGER_CMD_NEW_SINK ||
                header->type == LOGGER_CMD_LOG) {
            (*payload)[data_len - 1] = '\0';
        }
    } else {
        *payload = NULL;
    }

    free(plain);
    return 1;

fail_close_fd:
    if (*received_fd >= 0) {
        close(*received_fd);
        *received_fd = -1;
    }
    return -1;
}

static struct ChildSink *
child_sink_lookup(struct ChildSink_head *head, uint32_t id) {
    struct ChildSink *sink = SLIST_FIRST(head);

    while (sink != NULL) {
        if (sink->id == id)
            return sink;
        sink = SLIST_NEXT(sink, entries);
    }

    return NULL;
}

static void
child_sink_free(struct ChildSink_head *head, struct ChildSink *sink) {
    if (sink == NULL)
        return;

    SLIST_REMOVE(head, sink, ChildSink, entries);
    if (sink->type == LOG_SINK_FILE && sink->file != NULL)
        fclose(sink->file);
    else if (sink->type == LOG_SINK_SYSLOG)
        closelog();
    sink->file = NULL;
    free(sink->filepath);
    sink->filepath = NULL;
    free(sink);
}

static FILE *
logger_child_open_file(const char *filepath) {
    int fd;
    struct stat st;

    if (filepath == NULL)
        return NULL;

    int open_flags = O_WRONLY | O_APPEND | O_CREAT;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif

    fd = open(filepath, open_flags, 0600);
    if (fd < 0)
        return NULL;

    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }

    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        (void)fchmod(fd, st.st_mode & ~(S_IWGRP | S_IWOTH));

    FILE *file = fdopen(fd, "a");
    if (file == NULL) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    setvbuf(file, NULL, _IOLBF, 0);

    return file;
}

static int
logger_prepare_sink_fd(struct LogSink *sink) {
    if (sink == NULL || sink->type != LOG_SINK_FILE)
        return -1;

    int fd = -1;

    if (sink->fd != NULL && sink->fd_owned) {
        fd = dup(fileno(sink->fd));
        if (fd < 0)
            return -1;
    } else if (!logger_parent_fs_locked && sink->filepath != NULL) {
        int open_flags = O_WRONLY | O_APPEND | O_CREAT;
#ifdef O_CLOEXEC
        open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        open_flags |= O_NOFOLLOW;
#endif
        fd = open(sink->filepath, open_flags, 0600);
        if (fd < 0)
            return -1;
    } else {
        errno = EACCES;
        return -1;
    }

    if (set_cloexec(fd) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    return fd;
}

static int
logger_register_sink(struct LogSink *sink) {
    if (sink == NULL || !logger_process_enabled)
        return 0;

    int fd_for_child = -1;
    if (sink->type == LOG_SINK_FILE) {
        fd_for_child = logger_prepare_sink_fd(sink);
        if (fd_for_child < 0) {
            if (!(errno == EACCES && sink->filepath != NULL))
                return -1;
            fd_for_child = -1;
        }
    }

    return send_logger_new_sink(sink, fd_for_child);
}

static void
logger_resend_sinks(void) {
    if (!logger_process_enabled)
        return;

    struct LogSink *sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (logger_register_sink(sink) < 0) {
            err("failed to register log sink %u with logger process: %s",
                    sink->id, strerror(errno));
            disable_logger_process();
            break;
        }
        sink = SLIST_NEXT(sink, entries);
    }
}

static void
logger_child_handle_message(int sockfd, struct logger_ipc_header *header,
        int received_fd, char *payload) {
    struct ChildSink *sink;

    switch (header->type) {
        case LOGGER_CMD_NEW_SINK:
            sink = calloc(1, sizeof(*sink));
            if (sink == NULL) {
                if (received_fd >= 0)
                    close(received_fd);
                break;
            }
            sink->id = header->sink_id;
            sink->type = (int)header->arg0;
            sink->file = NULL;
            sink->filepath = NULL;

            if (payload != NULL) {
                sink->filepath = strdup(payload);
                if (sink->filepath == NULL) {
                    if (received_fd >= 0)
                        close(received_fd);
                    free(sink);
                    break;
                }
            }

            if (sink->type == LOG_SINK_FILE) {
                if (received_fd >= 0) {
                    sink->file = fdopen(received_fd, "a");
                    if (sink->file == NULL) {
                        close(received_fd);
                        free(sink->filepath);
                        free(sink);
                        break;
                    }
                    setvbuf(sink->file, NULL, _IOLBF, 0);
                } else if (sink->filepath != NULL) {
                    sink->file = logger_child_open_file(sink->filepath);
                    if (sink->file == NULL) {
                        free(sink->filepath);
                        free(sink);
                        break;
                    }
                }
                if (received_fd < 0 && sink->file == NULL) {
                    free(sink->filepath);
                    free(sink);
                    break;
                }
            } else if (sink->type == LOG_SINK_STDERR) {
                if (received_fd >= 0)
                    close(received_fd);
                sink->file = stderr;
            } else if (sink->type == LOG_SINK_SYSLOG) {
                if (received_fd >= 0)
                    close(received_fd);
                openlog(PACKAGE_NAME, LOG_PID, 0);
            } else {
                /* Unknown sink type */
                if (received_fd >= 0)
                    close(received_fd);
                free(sink->filepath);
                free(sink);
                break;
            }

            SLIST_INSERT_HEAD(&child_sink_head, sink, entries);
            break;
        case LOGGER_CMD_LOG:
            sink = child_sink_lookup(&child_sink_head, header->sink_id);
            if (sink == NULL)
                break;
            if (sink->type == LOG_SINK_SYSLOG) {
                if (payload != NULL) {
                    /* Strip trailing newline - syslog adds its own */
                    size_t plen = header->payload_len;
                    if (plen >= 2 && payload[plen - 2] == '\n')
                        payload[plen - 2] = '\0';
                    syslog((int)header->arg1 | (int)header->arg0, "%s", payload);
                }
            } else if (sink->file != NULL && payload != NULL &&
                    header->payload_len > 0) {
                size_t write_len = header->payload_len - 1;
                (void)fwrite(payload, 1, write_len, sink->file);
            }
            break;
        case LOGGER_CMD_REOPEN:
            sink = child_sink_lookup(&child_sink_head, header->sink_id);
            if (sink == NULL) {
                if (received_fd >= 0)
                    close(received_fd);
                break;
            }
            if (sink->type == LOG_SINK_FILE) {
                FILE *file = NULL;
                if (received_fd >= 0) {
                    file = fdopen(received_fd, "a");
                    if (file == NULL) {
                        close(received_fd);
                        break;
                    }
                    setvbuf(file, NULL, _IOLBF, 0);
                } else if (sink->filepath != NULL) {
                    file = logger_child_open_file(sink->filepath);
                    if (file == NULL)
                        break;
                }
                if (sink->file != NULL)
                    fclose(sink->file);
                sink->file = file;
            } else if (sink->type == LOG_SINK_SYSLOG) {
                if (received_fd >= 0)
                    close(received_fd);
                closelog();
                openlog(PACKAGE_NAME, LOG_PID, 0);
            } else {
                if (received_fd >= 0)
                    close(received_fd);
            }
            break;
        case LOGGER_CMD_PRIVILEGES:
            if (payload == NULL ||
                    header->payload_len != sizeof(struct logger_privileges_payload))
                break;
            if (geteuid() == 0) {
                struct logger_privileges_payload *priv =
                        (struct logger_privileges_payload *)payload;
                gid_t gid = (gid_t)priv->gid;
                uid_t uid = (uid_t)priv->uid;
                gid_t groups[1];

                groups[0] = gid;
                if (setgroups(1, groups) < 0) {
                    fprintf(stderr, "sniproxy logger: setgroups: %s\n",
                            strerror(errno));
                    logger_child_exit(EXIT_FAILURE);
                }
                if (setgid(gid) < 0) {
                    fprintf(stderr, "sniproxy logger: setgid: %s\n",
                            strerror(errno));
                    logger_child_exit(EXIT_FAILURE);
                }
                if (setuid(uid) < 0) {
                    fprintf(stderr, "sniproxy logger: setuid: %s\n",
                            strerror(errno));
                    logger_child_exit(EXIT_FAILURE);
                }
                /* Verify privileges were actually dropped */
                if (getuid() == 0 || geteuid() == 0 ||
                        getgid() == 0 || getegid() == 0) {
                    fprintf(stderr,
                            "sniproxy logger: failed to drop privileges\n");
                    logger_child_exit(EXIT_FAILURE);
                }
#ifdef __OpenBSD__
                /* Tighten pledge - no longer need id */
                if (pledge("stdio rpath wpath cpath fattr unix recvfd",
                            NULL) == -1) {
                    fprintf(stderr,
                            "logger: pledge tighten failed: %s\n",
                            strerror(errno));
                    logger_child_exit(EXIT_FAILURE);
                }
#endif
            }
            break;
        case LOGGER_CMD_DROP:
            sink = child_sink_lookup(&child_sink_head, header->sink_id);
            if (sink != NULL)
                child_sink_free(&child_sink_head, sink);
            if (received_fd >= 0)
                close(received_fd);
            break;
        case LOGGER_CMD_SHUTDOWN:
            sink = SLIST_FIRST(&child_sink_head);
            while (sink != NULL) {
                struct ChildSink *next = SLIST_NEXT(sink, entries);
                child_sink_free(&child_sink_head, sink);
                sink = next;
            }
            logger_child_exit(EXIT_SUCCESS);
        case LOGGER_CMD_PING:
            {
                /* Respond with PONG to indicate we're alive */
                struct logger_ipc_header pong = {
                    .type = LOGGER_CMD_PONG,
                    .sink_id = 0,
                    .arg0 = header->arg0, /* Echo back the ping ID */
                    .arg1 = 0,
                    .payload_len = 0,
                };
                (void)ipc_crypto_send_msg(&logger_crypto_child, sockfd,
                        &pong, sizeof(pong), -1);
            }
            break;
        default:
            break;
    }

    if (payload != NULL)
        free(payload);
    if (received_fd >= 0 && header->type != LOGGER_CMD_NEW_SINK &&
            header->type != LOGGER_CMD_REOPEN &&
            header->type != LOGGER_CMD_DROP)
        close(received_fd);
}

static void
logger_child_main(int sockfd) {
#ifdef __linux__
    (void)prctl(PR_SET_NAME, "sniproxy-logger", 0, 0, 0);
#endif
#ifdef HAVE_SETPROCTITLE
    setproctitle("sniproxy-logger");
#elif defined(__linux__)
    logger_set_process_title_fallback("sniproxy-logger");
#endif

    /* The logger child is forked during init_config(), before main()
     * sets signal(SIGPIPE, SIG_IGN).  On platforms without MSG_NOSIGNAL
     * (e.g. macOS), writing to the IPC socket after the parent closes
     * it would deliver SIGPIPE and kill the child. */
    signal(SIGPIPE, SIG_IGN);

#ifdef __OpenBSD__
    /* Need 'id' promise for setuid/setgid/setgroups when dropping privileges */
    if (pledge("stdio rpath wpath cpath fattr id unix recvfd", NULL) == -1) {
        fprintf(stderr, "logger: pledge failed: %s\n", strerror(errno));
        logger_child_exit(EXIT_FAILURE);
    }
#endif

    if (ipc_crypto_channel_init(&logger_crypto_child, LOGGER_IPC_CHANNEL_ID,
            IPC_CRYPTO_ROLE_CHILD) < 0) {
        fprintf(stderr, "logger child: failed to initialize crypto context\n");
        logger_child_exit(EXIT_FAILURE);
    }

    /* Install seccomp filter after initialization */
    if (seccomp_available()) {
        if (seccomp_install_filter(SECCOMP_PROCESS_LOGGER) < 0) {
            fprintf(stderr, "logger: failed to install seccomp filter: %s\n",
                    strerror(errno));
            logger_child_exit(EXIT_FAILURE);
        }
    }

    for (;;) {
        struct logger_ipc_header header;
        char *payload = NULL;
        int received_fd = -1;
        int ret = recv_logger_message(sockfd, &header, &payload,
                &received_fd);
        if (ret <= 0) {
            free(payload);
            break;
        }

        logger_child_handle_message(sockfd, &header, received_fd, payload);
    }

    close(sockfd);

    struct ChildSink *cs = SLIST_FIRST(&child_sink_head);
    while (cs != NULL) {
        struct ChildSink *next = SLIST_NEXT(cs, entries);
        child_sink_free(&child_sink_head, cs);
        cs = next;
    }

    logger_child_exit(EXIT_SUCCESS);
}

int
logger_process_is_active(void) {
    return logger_process_enabled;
}

void
logger_parent_notify_fs_locked(void) {
    logger_parent_fs_locked = 1;
}

/*
 * Logger health check implementation
 *
 * Periodically sends a PING to the logger child process and waits for a PONG
 * response. If the logger fails to respond, it is considered dead and the
 * process terminates with a fatal error.
 */

static int
logger_send_ping(void) {
    if (!logger_process_enabled || logger_sock < 0)
        return -1;

    logger_ping_id++;
    struct logger_ipc_header header = {
        .type = LOGGER_CMD_PING,
        .sink_id = 0,
        .arg0 = logger_ping_id,
        .arg1 = 0,
        .payload_len = 0,
    };

    if (send_logger_message(&header, NULL, 0, -1) < 0)
        return -1;

    logger_ping_pending = 1;
    return 0;
}

static int
logger_check_pong(void) {
    if (!logger_process_enabled || logger_sock < 0 || !logger_ping_pending)
        return -1;

    /* Non-blocking check: the parent socket is already O_NONBLOCK
     * and the child had 30 seconds to respond since the ping was sent.
     * Using poll(0) avoids blocking the event loop. */
    struct pollfd pfd;
    pfd.fd = logger_sock;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, 0);
    if (ret <= 0)
        return -1; /* No response or error */

    /* Try to receive the PONG */
    uint8_t *msg = NULL;
    size_t msg_len = 0;
    int received_fd = -1;

    ret = ipc_crypto_recv_msg(&logger_crypto_parent, logger_sock,
            sizeof(struct logger_ipc_header), &msg, &msg_len, &received_fd);

    if (received_fd >= 0)
        close(received_fd);

    if (ret <= 0 || msg == NULL || msg_len < sizeof(struct logger_ipc_header)) {
        free(msg);
        return -1;
    }

    struct logger_ipc_header *pong = (struct logger_ipc_header *)msg;
    if (pong->type != LOGGER_CMD_PONG || pong->arg0 != logger_ping_id) {
        free(msg);
        return -1;
    }

    free(msg);
    logger_ping_pending = 0;
    return 0;
}

static int
logger_restart_child(void) {
    disable_logger_process();
    logger_process_failed = 0;
    return ensure_logger_process();
}

static void
logger_health_check_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    (void)w;
    (void)revents;

    if (!logger_process_enabled) {
        ev_timer_stop(loop, &logger_health_timer);
        logger_health_check_active = 0;
        return;
    }

    /* Check if previous ping got a response */
    if (logger_ping_pending) {
        if (logger_check_pong() < 0) {
            logger_ping_pending = 0;
            err("Logger health check: no response to ping, restarting");
            if (logger_restart_child()) {
                /* Restart succeeded, continue health checks */
                return;
            }
            err("Logger restart failed, falling back to in-process logging");
            ev_timer_stop(loop, &logger_health_timer);
            logger_health_check_active = 0;
            return;
        }
    }

    /* Send new ping */
    if (logger_send_ping() < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        err("Logger health check: unable to send ping, restarting");
        if (logger_restart_child()) {
            return;
        }
        err("Logger restart failed, falling back to in-process logging");
        ev_timer_stop(loop, &logger_health_timer);
        logger_health_check_active = 0;
    }
}

void
logger_start_health_check(struct ev_loop *loop) {
    if (loop == NULL || !logger_process_enabled)
        return;

    if (logger_health_check_active)
        return;

    logger_health_loop = loop;
    logger_ping_pending = 0;
    logger_ping_id = 0;

    ev_timer_init(&logger_health_timer, logger_health_check_cb,
            LOGGER_HEALTH_CHECK_INTERVAL, LOGGER_HEALTH_CHECK_INTERVAL);
    ev_timer_start(loop, &logger_health_timer);
    logger_health_check_active = 1;
}

void
logger_stop_health_check(void) {
    if (!logger_health_check_active || logger_health_loop == NULL)
        return;

    ev_timer_stop(logger_health_loop, &logger_health_timer);
    logger_health_check_active = 0;
    logger_health_loop = NULL;
    logger_ping_pending = 0;
}

/* Global resolver debug flag */
static int resolver_debug_enabled = 0;

void
set_resolver_debug(int enabled) {
    resolver_debug_enabled = enabled;
}

int
get_resolver_debug(void) {
    return resolver_debug_enabled;
}
