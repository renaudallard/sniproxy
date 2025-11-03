/*
 * Copyright (c) 2013, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <assert.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef HAVE_SETPROCTITLE
#include <stdlib.h>
#endif
#include "logger.h"
#include "fd_util.h"

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

static struct Logger *default_logger = NULL;
static SLIST_HEAD(LogSink_head, LogSink) sinks = SLIST_HEAD_INITIALIZER(sinks);

static pid_t logger_pid = -1;
static int logger_sock = -1;
static uint32_t next_sink_id = 1;
static int logger_process_enabled = 0;
static int logger_process_failed = 0;
static int logger_parent_fs_locked = 0;

struct logger_ipc_header;

static void free_logger(struct Logger *);
static void init_default_logger(void);
static void vlog_msg(struct Logger *, int, const char *, va_list);
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
static int send_logger_header(const struct logger_ipc_header *, int);
static int send_logger_payload(const void *, size_t);
static int send_logger_new_sink(struct LogSink *, int fd_to_send);
static int send_logger_log(struct Logger *, int, const char *);
static int send_logger_reopen(struct LogSink *, int fd_to_send);
static int send_logger_drop(struct LogSink *);
static ssize_t write_full(int, const void *, size_t);
static ssize_t read_full(int, void *, size_t);
static int recv_logger_header(int, struct logger_ipc_header *, int *);
static int read_logger_payload(int, void *, size_t);
static void logger_child_handle_message(int, struct logger_ipc_header *, int, char *);
static struct ChildSink *child_sink_lookup(struct ChildSink_head *, uint32_t);
static void child_sink_free(struct ChildSink_head *, struct ChildSink *);
static FILE *logger_child_open_file(const char *filepath);

#define LOGGER_CMD_NEW_SINK   1U
#define LOGGER_CMD_LOG        2U
#define LOGGER_CMD_REOPEN     3U
#define LOGGER_CMD_DROP       4U
#define LOGGER_CMD_SHUTDOWN   5U

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
                    FILE *file = freopen(sink->filepath, "a", sink->fd);
                    if (file == NULL) {
                        err("failed to reopen local log file %s: %s",
                                sink->filepath, strerror(errno));
                        sink->fd = NULL;
                        sink->fd_owned = 0;
                    } else {
                        sink->fd = file;
                        sink->fd_owned = 1;
                        setvbuf(sink->fd, NULL, _IOLBF, 0);
                    }
                }
            } else {
                if (!logger_parent_fs_locked) {
                    sink->fd = freopen(sink->filepath, "a", sink->fd);
                    if (sink->fd == NULL)
                        err("failed to reopen log file %s: %s",
                                sink->filepath, strerror(errno));
                    else
                        setvbuf(sink->fd, NULL, _IOLBF, 0);
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
set_default_logger(struct Logger *new_logger) {
    struct Logger *old_default_logger = default_logger;

    assert(new_logger != NULL);
    default_logger = logger_ref_get(new_logger);
    logger_ref_put(old_default_logger);
}

void
set_logger_priority(struct Logger *logger, int priority) {
    assert(logger != NULL);
    assert(priority >= LOG_EMERG && priority <= LOG_DEBUG);
    logger->priority = priority;
}

void
logger_ref_put(struct Logger *logger) {
    if (logger == NULL)
        return;

    assert(logger->reference_count > 0);
    logger->reference_count--;
    if (logger->reference_count == 0)
        free_logger(logger);
}

struct Logger *
logger_ref_get(struct Logger *logger) {
    if (logger != NULL)
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
    assert(logger != NULL);

    if (priority > logger->priority)
        return;

    if (logger_process_enabled && logger->sink != NULL) {
        char buffer[1024];
        size_t len = timestamp(buffer, sizeof(buffer));
        int remaining = (int)(sizeof(buffer) - len);
        if (remaining < 0)
            remaining = 0;
        int written = vsnprintf(buffer + len, (size_t)remaining, format, args);
        if (written < 0)
            return;
        size_t total = len + (size_t)written;
        if (total >= sizeof(buffer))
            total = sizeof(buffer) - 1;
        if (total + 2 >= sizeof(buffer))
            total = sizeof(buffer) - 2;
        buffer[total++] = '\n';
        buffer[total] = '\0';
        if (send_logger_log(logger, priority, buffer) == 0)
            return;

        disable_logger_process();
    }

    if (logger->sink->type == LOG_SINK_SYSLOG) {
        vsyslog(logger->facility | priority, format, args);
    } else if (logger->sink->fd != NULL) {
        char buffer[1024];

        size_t len = timestamp(buffer, sizeof(buffer));

        vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
        buffer[sizeof(buffer) - 1] = '\0'; /* ensure buffer null terminated */

        fprintf(logger->sink->fd, "%s\n", buffer);
    }
}

static void
init_default_logger(void) {
    struct Logger *logger = NULL;

    if (default_logger != NULL)
        return;

    if (!ensure_logger_process())
        logger_process_enabled = 0;

    logger = calloc(1, sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_stderr_sink();
        if (logger->sink == NULL) {
            free(logger);
            return;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = 0;
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    if (logger == NULL)
        return;

    if (!logger_process_initialized) {
        atexit(free_at_exit);
        logger_process_initialized = 1;
    }

    default_logger = logger_ref_get(logger);
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

    size_t facility_len = strlen(facility);

    for (size_t i = 0; i < sizeof(facilities) / sizeof(facilities[0]); i++)
        if (strncasecmp(facilities[i].name, facility, facility_len) == 0)
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
                err("failed to register stderr sink with logger process: %s",
                        strerror(errno));
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
            err("Failed to open new log file: %s", filepath);
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
        if (send_logger_new_sink(sink, fd_for_child) < 0) {
            err("Failed to register log file %s with logger process: %s", filepath,
                    strerror(errno));
            if (sink->fd != NULL && sink->fd_owned) {
                fclose(sink->fd);
                sink->fd = NULL;
                sink->fd_owned = 0;
            }
            free((char *)sink->filepath);
            free(sink);
            disable_logger_process();
            return NULL;
        }
    } else if (sink->fd == NULL) {
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
            err("Failed to open new log file: %s", filepath);
            return NULL;
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
    }

    SLIST_INSERT_HEAD(&sinks, sink, entries);

    return sink;
}

static struct LogSink *
log_sink_ref_get(struct LogSink *sink) {
    if (sink != NULL)
        sink->reference_count++;

    return sink;
}

static void
log_sink_ref_put(struct LogSink *sink) {
    if (sink == NULL)
        return;

    assert(sink->reference_count > 0);
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
            assert(0);
    }

    free(sink);
}

static size_t
timestamp(char *dst, size_t dst_len) {
    /* TODO change to ev_now() */
    time_t now = time(NULL);
    static struct {
        time_t when;
        char string[32];
        size_t len;
    } timestamp_cache = { .when = 0, .string = {'\0'}, .len = 0 };

    if (now != timestamp_cache.when) {
#ifdef RFC3339_TIMESTAMP
        struct tm *tmp = gmtime(&now);
        timestamp_cache.len = strftime(timestamp_cache.string,
                sizeof(timestamp_cache.string), "%FT%TZ ", tmp);
#else
        struct tm *tmp = localtime(&now);
        timestamp_cache.len = strftime(timestamp_cache.string,
                sizeof(timestamp_cache.string), "%F %T ", tmp);
#endif

        timestamp_cache.when = now;
    }

    if (dst == NULL)
        return timestamp_cache.len;

    if (dst_len == 0)
        return 0;

    size_t copy_len = timestamp_cache.len;

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
        if (waitpid(logger_pid, NULL, 0) < 0 && errno != ECHILD) {
            /* ignore waitpid failures other than no-child */
        }
        logger_pid = -1;
    }

    logger_process_enabled = 0;
    logger_process_failed = 1;

    struct LogSink *sink = SLIST_FIRST(&sinks);
    while (sink != NULL) {
        if (sink->type == LOG_SINK_FILE && sink->fd == NULL && sink->filepath != NULL) {
            if (!logger_parent_fs_locked) {
                FILE *file = fopen(sink->filepath, "a");
                if (file != NULL) {
                    setvbuf(file, NULL, _IOLBF, 0);
                    sink->fd = file;
                    sink->fd_owned = 1;
                }
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
        logger_child_main(sockets[1]);
    }

    close(sockets[1]);
    logger_sock = sockets[0];
    logger_pid = pid;
    logger_process_enabled = 1;

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
        send_logger_header(&header, -1);
        close(logger_sock);
        logger_sock = -1;
    }

    if (logger_pid > 0)
        waitpid(logger_pid, NULL, 0);

    logger_pid = -1;
    logger_process_enabled = 0;
}

static int
send_logger_header(const struct logger_ipc_header *header, int fd_to_send) {
    if (logger_sock < 0)
        return -1;

    struct msghdr msg;
    struct iovec iov;
    char control_buf[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    memset(&control_buf, 0, sizeof(control_buf));

    iov.iov_base = (void *)header;
    iov.iov_len = sizeof(*header);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd_to_send >= 0) {
        msg.msg_control = control_buf;
        msg.msg_controllen = sizeof(control_buf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
    }

    ssize_t written = sendmsg(logger_sock, &msg, 0);
    if (written < 0)
        return -1;

    return (written == (ssize_t)sizeof(*header)) ? 0 : -1;
}

static int
send_logger_payload(const void *payload, size_t payload_len) {
    if (payload_len == 0)
        return 0;

    if (write_full(logger_sock, payload, payload_len) < 0)
        return -1;

    return 0;
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

    if (send_logger_header(&header, fd_to_send) < 0) {
        if (fd_to_send >= 0)
            close(fd_to_send);
        return -1;
    }

    if (payload != NULL) {
        int rc = send_logger_payload(payload, header.payload_len);
        if (fd_to_send >= 0)
            close(fd_to_send);
        return rc;
    }

    if (fd_to_send >= 0)
        close(fd_to_send);

    return 0;
}

static int
send_logger_log(struct Logger *logger, int priority, const char *message) {
    if (logger == NULL || logger->sink == NULL)
        return -1;

    struct logger_ipc_header header = {
        .type = LOGGER_CMD_LOG,
        .sink_id = logger->sink->id,
        .arg0 = (uint32_t)priority,
        .arg1 = (uint32_t)logger->facility,
        .payload_len = (uint32_t)(strlen(message) + 1),
    };

    if (send_logger_header(&header, -1) < 0)
        return -1;

    return send_logger_payload(message, header.payload_len);
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

    if (send_logger_header(&header, fd_to_send) < 0) {
        if (fd_to_send >= 0)
            close(fd_to_send);
        return -1;
    }

    if (fd_to_send >= 0)
        close(fd_to_send);

    return 0;
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

    return send_logger_header(&header, -1);
}

static ssize_t
write_full(int fd, const void *buf, size_t len) {
    const char *ptr = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = write(fd, ptr, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += (size_t)n;
        remaining -= (size_t)n;
    }

    return (ssize_t)len;
}

static ssize_t
read_full(int fd, void *buf, size_t len) {
    char *ptr = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = read(fd, ptr, remaining);
        if (n == 0)
            return len - remaining;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += (size_t)n;
        remaining -= (size_t)n;
    }

    return (ssize_t)len;
}

static int
recv_logger_header(int fd, struct logger_ipc_header *header, int *received_fd) {
    struct msghdr msg;
    struct iovec iov;
    char control_buf[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    memset(control_buf, 0, sizeof(control_buf));

    iov.iov_base = header;
    iov.iov_len = sizeof(*header);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);

    for (;;) {
        ssize_t ret = recvmsg(fd, &msg, MSG_WAITALL);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (ret == 0)
            return 0;
        if (ret != (ssize_t)sizeof(*header))
            return -1;
        break;
    }

    if ((msg.msg_flags & MSG_TRUNC) != 0)
        return -1;

    if (received_fd != NULL)
        *received_fd = -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
        if (received_fd != NULL)
            memcpy(received_fd, CMSG_DATA(cmsg), sizeof(int));
    }

    return 1;
}

static int
read_logger_payload(int fd, void *buf, size_t len) {
    if (len == 0)
        return 0;

    if (read_full(fd, buf, len) < 0)
        return -1;

    return 0;
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

static void
logger_child_handle_message(int sockfd, struct logger_ipc_header *header,
        int received_fd, char *payload) {
    (void)sockfd;
    struct ChildSink *sink;

    switch (header->type) {
        case LOGGER_CMD_NEW_SINK:
            sink = malloc(sizeof(*sink));
            if (sink == NULL)
                break;
            sink->id = header->sink_id;
            sink->type = (int)header->arg0;
            sink->file = NULL;
            sink->filepath = NULL;

            if (payload != NULL) {
                sink->filepath = strdup(payload);
                if (sink->filepath == NULL) {
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
                sink->file = stderr;
            } else if (sink->type == LOG_SINK_SYSLOG) {
                openlog(PACKAGE_NAME, LOG_PID, 0);
            }

            SLIST_INSERT_HEAD(&child_sink_head, sink, entries);
            break;
        case LOGGER_CMD_LOG:
            sink = child_sink_lookup(&child_sink_head, header->sink_id);
            if (sink == NULL)
                break;
            if (sink->type == LOG_SINK_SYSLOG) {
                if (payload != NULL)
                    syslog((int)header->arg1 | (int)header->arg0, "%s", payload);
            } else if (sink->file != NULL && payload != NULL) {
                fputs(payload, sink->file);
            }
            break;
        case LOGGER_CMD_REOPEN:
            sink = child_sink_lookup(&child_sink_head, header->sink_id);
            if (sink == NULL)
                break;
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
                closelog();
                openlog(PACKAGE_NAME, LOG_PID, 0);
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
            _exit(EXIT_SUCCESS);
        default:
            break;
    }

    if (payload != NULL)
        free(payload);
    if (received_fd >= 0 && header->type != LOGGER_CMD_NEW_SINK && header->type != LOGGER_CMD_REOPEN)
        close(received_fd);
}

static void
logger_child_main(int sockfd) {
#ifdef __linux__
    (void)prctl(PR_SET_NAME, "sniproxy-logger", 0, 0, 0);
#endif
#ifdef HAVE_SETPROCTITLE
    setproctitle("sniproxy-logger");
#endif

    for (;;) {
        struct logger_ipc_header header;
        int received_fd = -1;
        int ret = recv_logger_header(sockfd, &header, &received_fd);
        if (ret <= 0)
            break;

        char *payload = NULL;
        if (header.payload_len > 0) {
            payload = malloc(header.payload_len);
            if (payload == NULL) {
                if (received_fd >= 0)
                    close(received_fd);
                continue;
            }
            if (read_logger_payload(sockfd, payload, header.payload_len) < 0) {
                free(payload);
                if (received_fd >= 0)
                    close(received_fd);
                continue;
            }
            payload[header.payload_len - 1] = '\0';
        }

        logger_child_handle_message(sockfd, &header, received_fd, payload);
    }

    close(sockfd);
    _exit(EXIT_SUCCESS);
}

int
logger_process_is_active(void) {
    return logger_process_enabled;
}

void
logger_parent_notify_fs_locked(void) {
    logger_parent_fs_locked = 1;
}
