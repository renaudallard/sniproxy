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

#ifndef EV_H
#define EV_H

#include <stdlib.h>

typedef double ev_tstamp;

#define EVFLAG_AUTO        0u
#define EVFLAG_FORKCHECK   0u
#define EVFLAG_NOENV       0u
#define EVFLAG_SIGNALFD    0u
#define EVFLAG_NOINOTIFY   0u

#define EV_READ  0x01u
#define EV_WRITE 0x02u
#define EV_TIMER 0x04u

#define EVBREAK_ALL   0
#define EVUNLOOP_ALL  0

#define EV_WATCHER_FIELDS \
    int active; \
    int pending; \
    void *data;

struct ev_watcher {
    EV_WATCHER_FIELDS
};

struct ev_loop {
    int is_default;
};

struct ev_io {
    EV_WATCHER_FIELDS
    int fd;
    int events;
};

struct ev_timer {
    EV_WATCHER_FIELDS
    ev_tstamp repeat;
    ev_tstamp at;
};

struct ev_signal {
    EV_WATCHER_FIELDS
    int signum;
};

typedef void (*ev_io_cb)(struct ev_loop *, struct ev_io *, int);
typedef void (*ev_timer_cb)(struct ev_loop *, struct ev_timer *, int);
typedef void (*ev_signal_cb)(struct ev_loop *, struct ev_signal *, int);

static inline struct ev_loop *
ev_stub_default_loop(void) {
    static struct ev_loop default_loop = {1};
    return &default_loop;
}

#define EV_DEFAULT ev_stub_default_loop()

static inline struct ev_loop *
ev_loop_new(unsigned int flags) {
    (void)flags;
    return calloc(1, sizeof(struct ev_loop));
}

static inline struct ev_loop *
ev_default_loop(unsigned int flags) {
    (void)flags;
    return EV_DEFAULT;
}

static inline void
ev_loop_destroy(struct ev_loop *loop) {
    if (loop == NULL || loop == EV_DEFAULT)
        return;
    free(loop);
}

static inline void
ev_run(struct ev_loop *loop, int flags) {
    (void)loop;
    (void)flags;
}

static inline void
ev_break(struct ev_loop *loop, int how) {
    (void)loop;
    (void)how;
}

static inline void
ev_unloop(struct ev_loop *loop, int how) {
    (void)loop;
    (void)how;
}

static inline ev_tstamp
ev_now(struct ev_loop *loop) {
    (void)loop;
    return 0.0;
}

static inline ev_tstamp
ev_time(void) {
    return 0.0;
}

static inline void
ev_default_fork(void) {}

static inline void
ev_set_io_collect_interval(struct ev_loop *loop, ev_tstamp interval) {
    (void)loop;
    (void)interval;
}

static inline void
ev_set_timeout_collect_interval(struct ev_loop *loop, ev_tstamp interval) {
    (void)loop;
    (void)interval;
}

static inline void
ev_io_init(struct ev_io *w, ev_io_cb cb, int fd, int events) {
    (void)cb;
    if (w == NULL)
        return;
    w->fd = fd;
    w->events = events;
    w->active = 0;
    w->pending = 0;
}

static inline void
ev_io_set(struct ev_io *w, int fd, int events) {
    if (w == NULL)
        return;
    w->fd = fd;
    w->events = events;
}

static inline void
ev_io_start(struct ev_loop *loop, struct ev_io *w) {
    (void)loop;
    if (w != NULL)
        w->active = 1;
}

static inline void
ev_io_stop(struct ev_loop *loop, struct ev_io *w) {
    (void)loop;
    if (w != NULL)
        w->active = 0;
}

static inline void
ev_timer_init(struct ev_timer *w, ev_timer_cb cb, ev_tstamp after, ev_tstamp repeat) {
    (void)cb;
    if (w == NULL)
        return;
    w->at = after;
    w->repeat = repeat;
    w->active = 0;
    w->pending = 0;
}

static inline void
ev_timer_set(struct ev_timer *w, ev_tstamp after, ev_tstamp repeat) {
    if (w == NULL)
        return;
    w->at = after;
    w->repeat = repeat;
}

static inline void
ev_timer_start(struct ev_loop *loop, struct ev_timer *w) {
    (void)loop;
    if (w != NULL)
        w->active = 1;
}

static inline void
ev_timer_stop(struct ev_loop *loop, struct ev_timer *w) {
    (void)loop;
    if (w != NULL)
        w->active = 0;
}

static inline void
ev_signal_init(struct ev_signal *w, ev_signal_cb cb, int signum) {
    (void)cb;
    if (w == NULL)
        return;
    w->signum = signum;
    w->active = 0;
    w->pending = 0;
}

static inline void
ev_signal_start(struct ev_loop *loop, struct ev_signal *w) {
    (void)loop;
    if (w != NULL)
        w->active = 1;
}

static inline void
ev_signal_stop(struct ev_loop *loop, struct ev_signal *w) {
    (void)loop;
    if (w != NULL)
        w->active = 0;
}

static inline int
ev_is_active(const void *w_) {
    const struct ev_watcher *w = (const struct ev_watcher *)w_;
    return (w != NULL && w->active);
}

static inline int
ev_is_pending(const void *w_) {
    const struct ev_watcher *w = (const struct ev_watcher *)w_;
    return (w != NULL && w->pending);
}

static inline void
ev_clear_pending(struct ev_loop *loop, void *w_) {
    (void)loop;
    struct ev_watcher *w = (struct ev_watcher *)w_;
    if (w != NULL)
        w->pending = 0;
}

#endif /* EV_H */
