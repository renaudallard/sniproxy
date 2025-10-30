#ifndef EV_H
#define EV_H

typedef double ev_tstamp;

struct ev_loop;

struct ev_io {
    int fd;
    void *data;
};

struct ev_timer {
    void *data;
};

typedef void (*ev_io_cb)(struct ev_loop *, struct ev_io *, int);
typedef void (*ev_timer_cb)(struct ev_loop *, struct ev_timer *, int);

#define EV_READ 0x01
#define EV_TIMER 0x02

static inline ev_tstamp ev_now(struct ev_loop *loop) {
    (void)loop;
    return 0.0;
}

static inline void ev_io_init(struct ev_io *w, ev_io_cb cb, int fd, int events) {
    (void)cb;
    (void)events;
    if (w != NULL)
        w->fd = fd;
}

static inline void ev_io_set(struct ev_io *w, int fd, int events) {
    (void)events;
    if (w != NULL)
        w->fd = fd;
}

static inline void ev_io_start(struct ev_loop *loop, struct ev_io *w) {
    (void)loop;
    (void)w;
}

static inline void ev_io_stop(struct ev_loop *loop, struct ev_io *w) {
    (void)loop;
    (void)w;
}

static inline void ev_timer_init(struct ev_timer *w, ev_timer_cb cb, ev_tstamp after, ev_tstamp repeat) {
    (void)w;
    (void)cb;
    (void)after;
    (void)repeat;
}

static inline void ev_timer_set(struct ev_timer *w, ev_tstamp after, ev_tstamp repeat) {
    (void)w;
    (void)after;
    (void)repeat;
}

static inline void ev_timer_start(struct ev_loop *loop, struct ev_timer *w) {
    (void)loop;
    (void)w;
}

static inline void ev_timer_stop(struct ev_loop *loop, struct ev_timer *w) {
    (void)loop;
    (void)w;
}

#endif /* EV_H */
