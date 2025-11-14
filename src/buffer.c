/*
 * Copyright (c) 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stdlib.h> /* malloc, realloc */
#include <string.h> /* memcpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <ev.h>
#include "buffer.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define NOT_POWER_OF_2(x) (x == 0 || (x & (x - 1)))


#define BUFFER_COALESCE_STACK_COPY 4096
static const size_t BUFFER_MAX_SIZE = 10 * 1024 * 1024;

struct BufferPoolClass {
    size_t size;
    size_t max_cached;
    size_t cached;
    void *head;
};

static struct BufferPoolClass buffer_pool_classes[] = {
    { 8192, 512, 0, NULL },
    { 16384, 256, 0, NULL },
    { 65536, 64, 0, NULL },
};

static void *buffer_pool_acquire(size_t size, int *pooled);
static int buffer_pool_release(size_t size, void *ptr);

static size_t setup_write_iov(const struct Buffer *, struct iovec *, size_t);
static size_t setup_read_iov(const struct Buffer *, struct iovec *, size_t);
static inline void advance_write_position(struct Buffer *, size_t);
static inline void advance_read_position(struct Buffer *, size_t);
static size_t next_power_of_two(size_t);
static void buffer_release_storage(int from_pool, size_t size, char *ptr);


static void (*buffer_memory_observer)(ssize_t delta);

static void *
buffer_pool_acquire(size_t size, int *pooled) {
    if (pooled != NULL)
        *pooled = 0;

    for (size_t i = 0; i < sizeof(buffer_pool_classes) / sizeof(buffer_pool_classes[0]); i++) {
        struct BufferPoolClass *cls = &buffer_pool_classes[i];
        if (cls->size != size || cls->head == NULL)
            continue;

        void *mem = cls->head;
        void *next = *(void **)mem;
        cls->head = next;
        if (cls->cached > 0)
            cls->cached--;
        memset(mem, 0, cls->size);
        if (pooled != NULL)
            *pooled = 1;
        return mem;
    }

    return NULL;
}

static int
buffer_pool_release(size_t size, void *ptr) {
    if (ptr == NULL)
        return 0;

    for (size_t i = 0; i < sizeof(buffer_pool_classes) / sizeof(buffer_pool_classes[0]); i++) {
        struct BufferPoolClass *cls = &buffer_pool_classes[i];
        if (cls->size != size)
            continue;
        if (cls->cached >= cls->max_cached)
            return 0;

        memset(ptr, 0, size);
        *(void **)ptr = cls->head;
        cls->head = ptr;
        cls->cached++;
        return 1;
    }

    return 0;
}



static void
buffer_release_storage(int from_pool, size_t size, char *ptr) {
    if (ptr == NULL)
        return;

    if (from_pool) {
        if (!buffer_pool_release(size, ptr)) {
            memset(ptr, 0, size);
            free(ptr);
        }
        return;
    }

    memset(ptr, 0, size);
    free(ptr);
}

static inline void
buffer_notify_memory(ssize_t delta) {
    if (buffer_memory_observer != NULL && delta != 0)
        buffer_memory_observer(delta);
}

void
buffer_set_memory_observer(void (*observer)(ssize_t delta)) {
    buffer_memory_observer = observer;
}

struct Buffer *
new_buffer(size_t size, struct ev_loop *loop) {
    if (NOT_POWER_OF_2(size))
        return NULL;
    struct Buffer *buf = malloc(sizeof(struct Buffer));
    if (buf == NULL)
        return NULL;

    buffer_notify_memory((ssize_t)sizeof(struct Buffer));

    buf->min_size = size;
    buf->size_mask = size - 1;
    buf->len = 0;
    buf->head = 0;
    buf->max_size = BUFFER_MAX_SIZE;
    buf->tx_bytes = 0;
    buf->rx_bytes = 0;
    const ev_tstamp now = ev_now(loop);
    buf->last_recv = now;
    buf->last_send = now;
    int from_pool = 0;
    char *data = buffer_pool_acquire(size, &from_pool);
    if (data == NULL)
        data = malloc(size);
    if (data == NULL) {
        buffer_notify_memory(-(ssize_t)sizeof(struct Buffer));
        free(buf);
        return NULL;
    }

    buf->buffer = data;
    buf->pool_managed = from_pool;
    buffer_notify_memory((ssize_t)size);

    return buf;
}

ssize_t
buffer_resize(struct Buffer *buf, size_t new_size) {
    if (NOT_POWER_OF_2(new_size))
        return -4;

    if (new_size > buf->max_size)
        return -3;

    if (new_size < buf->len)
        return -1; /* new_size too small to hold existing data */

    size_t current_size = buffer_size(buf);

    if (new_size == current_size)
        return (ssize_t)buf->len;

    size_t used_end = buf->len == 0 ? 0 : buf->head + buf->len;
    int data_is_contiguous = (buf->len == 0) || used_end <= current_size;
    int was_pooled = buf->pool_managed;

    if (buf->len == 0) {
        if (was_pooled) {
            int pooled = 0;
            char *replacement = buffer_pool_acquire(new_size, &pooled);
            if (replacement == NULL)
                replacement = malloc(new_size);
            if (replacement == NULL)
                return -2;

            buffer_release_storage(was_pooled, current_size, buf->buffer);
            buf->buffer = replacement;
            buf->pool_managed = pooled;
            buf->size_mask = new_size - 1;
            buf->head = 0;
        } else {
            char *resized = realloc(buf->buffer, new_size);
            if (resized == NULL)
                return -2;

            buf->buffer = resized;
            buf->size_mask = new_size - 1;
            buf->head = 0;
        }
    } else if (data_is_contiguous && used_end <= new_size && !was_pooled) {
        char *resized = realloc(buf->buffer, new_size);
        if (resized == NULL)
            return -2;

        buf->buffer = resized;
        buf->size_mask = new_size - 1;
    } else {
        int pooled = 0;
        char *new_buffer = buffer_pool_acquire(new_size, &pooled);
        if (new_buffer == NULL)
            new_buffer = malloc(new_size);
        if (new_buffer == NULL)
            return -2;

        size_t first_len = MIN(buf->len, current_size - buf->head);
        memcpy(new_buffer, buf->buffer + buf->head, first_len);
        if (buf->len > first_len)
            memcpy(new_buffer + first_len, buf->buffer, buf->len - first_len);

        buffer_release_storage(was_pooled, current_size, buf->buffer);
        buf->buffer = new_buffer;
        buf->head = 0;
        buf->size_mask = new_size - 1;
        buf->pool_managed = pooled;
    }


    buffer_notify_memory((ssize_t)new_size - (ssize_t)current_size);

    if (new_size < buf->min_size)
        buf->min_size = new_size;

    return (ssize_t)buf->len;
}

int
buffer_reserve(struct Buffer *buf, size_t min_room) {
    if (min_room == 0 || buffer_room(buf) >= min_room)
        return 0;

    if (min_room > SIZE_MAX - buf->len)
        return -1;

    if (buf->len >= buf->max_size || min_room > buf->max_size - buf->len)
        return -1;

    size_t required = buf->len + min_room;
    size_t current_size = buffer_size(buf);
    size_t new_size = next_power_of_two(required);

    if (new_size == 0 || new_size > buf->max_size)
        return -1;

    if (new_size < current_size)
        new_size = current_size;

    if (new_size == current_size)
        return 0;

    return buffer_resize(buf, new_size) < 0 ? -1 : 0;
}

void
buffer_set_max_size(struct Buffer *buf, size_t max_size) {
    if (buf == NULL)
        return;

    if (max_size == 0 || max_size > BUFFER_MAX_SIZE)
        max_size = BUFFER_MAX_SIZE;

    size_t current_size = buffer_size(buf);
    if (max_size < current_size)
        max_size = current_size;

    buf->max_size = max_size;
}


int
buffer_maybe_shrink(struct Buffer *buf) {
    size_t current_size = buffer_size(buf);

    if (current_size <= buf->min_size)
        return 0;

    if (buf->len > current_size / 4)
        return 0;

    /* Keep at least a 2x growth slack to avoid resize thrashing. */
    size_t desired = buf->len ? buf->len << 1 : 1;

    if (desired < buf->min_size)
        desired = buf->min_size;

    size_t new_size = next_power_of_two(desired);

    if (new_size == 0 || new_size >= current_size)
        return 0;

    return buffer_resize(buf, new_size) < 0 ? -1 : 0;
}

int
buffer_maybe_shrink_idle(struct Buffer *buf, ev_tstamp now, ev_tstamp idle_age) {
    if (buf == NULL)
        return 0;

    if (buf->len != 0)
        return 0;

    ev_tstamp last_activity = buf->last_recv > buf->last_send ?
            buf->last_recv : buf->last_send;

    if (now - last_activity < idle_age)
        return 0;

    return buffer_maybe_shrink(buf);
}

void
free_buffer(struct Buffer *buf) {
    if (buf == NULL)
        return;

    if (buf->buffer != NULL) {
        size_t current_size = buffer_size(buf);
        buffer_notify_memory(-(ssize_t)current_size);
        buffer_release_storage(buf->pool_managed, current_size, buf->buffer);
        buf->buffer = NULL;
    }

    buffer_notify_memory(-(ssize_t)sizeof(struct Buffer));
    free(buf);
}

ssize_t
buffer_recv(struct Buffer *buffer, int sockfd, int flags, struct ev_loop *loop) {
    /* coalesce when reading into an empty buffer */
    if (buffer->len == 0)
        buffer->head = 0;

    struct iovec iov[2];
    struct msghdr msg = {
        .msg_iov = iov,
        .msg_iovlen = setup_write_iov(buffer, iov, 0)
    };

    ssize_t bytes = recvmsg(sockfd, &msg, flags);

    buffer->last_recv = ev_now(loop);

    if (bytes > 0)
        advance_write_position(buffer, (size_t)bytes);

    return bytes;
}

ssize_t
buffer_send(struct Buffer *buffer, int sockfd, int flags, struct ev_loop *loop) {
    struct iovec iov[2];
    struct msghdr msg = {
        .msg_iov = iov,
        .msg_iovlen = setup_read_iov(buffer, iov, 0)
    };

    ssize_t bytes = sendmsg(sockfd, &msg, flags);

    buffer->last_send = ev_now(loop);

    if (bytes > 0)
        advance_read_position(buffer, (size_t)bytes);

    return bytes;
}

/*
 * Read data from file into buffer
 */
ssize_t
buffer_read(struct Buffer *buffer, int fd) {
    /* coalesce when reading into an empty buffer */
    if (buffer->len == 0)
        buffer->head = 0;

    struct iovec iov[2];
    size_t iov_len = setup_write_iov(buffer, iov, 0);
    ssize_t bytes = readv(fd, iov, iov_len);

    if (bytes > 0)
        advance_write_position(buffer, (size_t)bytes);

    return bytes;
}

/*
 * Write data to file from buffer
 */
ssize_t
buffer_write(struct Buffer *buffer, int fd) {
    struct iovec iov[2];
    size_t iov_len = setup_read_iov(buffer, iov, 0);
    ssize_t bytes = writev(fd, iov, iov_len);

    if (bytes > 0)
        advance_read_position(buffer, (size_t)bytes);

    return bytes;
}

/*
 * Coalesce a buffer into a single continuous region, optionally returning a
 * pointer to that region.
 *
 * Returns the size of the buffer contents
 */
size_t
buffer_coalesce(struct Buffer *buffer, const void **dst) {
    size_t len = buffer->len;
    size_t head = buffer->head;
    size_t size = buffer_size(buffer);

    if (len == 0) {
        if (dst != NULL)
            *dst = buffer->buffer + head;

        return 0;
    }

    if (head + len <= size) {
        /* Buffer contents are already contiguous. */
        if (dst != NULL)
            *dst = buffer->buffer + head;

        return len;
    }

    size_t first_len = size - head;
    size_t second_len = len - first_len;
    size_t temp_len = first_len < second_len ? first_len : second_len;

    char stack_buf[BUFFER_COALESCE_STACK_COPY];
    char *temp = stack_buf;
    int temp_on_heap = 0;

    if (temp_len > BUFFER_COALESCE_STACK_COPY) {
        temp = malloc(temp_len);
        if (temp == NULL) {
            if (dst != NULL)
                *dst = buffer->buffer + head;

            return len;
        }
        temp_on_heap = 1;
    }

    if (first_len <= second_len) {
        memcpy(temp, buffer->buffer + head, first_len);
        memmove(buffer->buffer + first_len, buffer->buffer, second_len);
        memcpy(buffer->buffer, temp, first_len);
    } else {
        if (first_len >= second_len * 2) {
            memmove(buffer->buffer + second_len, buffer->buffer + head, first_len);
        } else {
            memcpy(temp, buffer->buffer, second_len);
            memmove(buffer->buffer, buffer->buffer + head, first_len);
            memcpy(buffer->buffer + first_len, temp, second_len);
        }
    }

    if (temp_on_heap)
        free(temp);

    buffer->head = 0;

    if (dst != NULL)
        *dst = buffer->buffer;

    return len;
}

size_t
buffer_peek(const struct Buffer *src, void *dst, size_t len) {
    size_t read_len = src->len;

    if (len != 0 && len < read_len)
        read_len = len;

    if (dst == NULL)
        return read_len;

    size_t head = src->head;
    size_t size = buffer_size(src);
    size_t first_len = MIN(read_len, size - head);

    memcpy(dst, src->buffer + head, first_len);

    if (read_len > first_len)
        memcpy((char *)dst + first_len, src->buffer, read_len - first_len);

    return read_len;
}

size_t
buffer_pop(struct Buffer *src, void *dst, size_t len) {
    size_t bytes = buffer_peek(src, dst, len);

    if (bytes > 0)
        advance_read_position(src, bytes);

    return bytes;
}

size_t
buffer_push(struct Buffer *dst, const void *src, size_t len) {
    if (len == 0)
        return 0;

    /* coalesce when reading into an empty buffer */
    if (dst->len == 0)
        dst->head = 0;

    if (buffer_reserve(dst, len) < 0)
        return 0; /* insufficient room */

    size_t start = (dst->head + dst->len) & dst->size_mask;
    const size_t size = buffer_size(dst);
    size_t first_len = MIN(len, size - start);

    memcpy(dst->buffer + start, src, first_len);

    if (len > first_len)
        memcpy(dst->buffer, (const char *)src + first_len, len - first_len);

    advance_write_position(dst, len);

    return len;
}

/*
 * Setup a struct iovec iov[2] for a write to a buffer.
 * struct iovec *iov MUST be at least length 2.
 * returns the number of entries setup
 */
static size_t
setup_write_iov(const struct Buffer *buffer, struct iovec *iov, size_t len) {
    const size_t size = buffer_size(buffer);
    size_t room = size - buffer->len;

    if (room == 0) /* trivial case: no room */
        return 0;

    size_t write_len = room;
    /* Allow caller to specify maximum length */
    if (len != 0)
        write_len = MIN(room, len);

    size_t start = (buffer->head + buffer->len) & buffer->size_mask;

    if (start + write_len <= size) {
        iov[0].iov_base = buffer->buffer + start;
        iov[0].iov_len = write_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + size);

        return 1;
    } else {
        iov[0].iov_base = buffer->buffer + start;
        iov[0].iov_len = size - start;
        iov[1].iov_base = buffer->buffer;
        iov[1].iov_len = write_len - iov[0].iov_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + size);
        assert(iov[1].iov_len > 0);
        assert((char *)iov[1].iov_base >= buffer->buffer);
        assert((char *)iov[1].iov_base + iov[1].iov_len <= (char *)iov[0].iov_base);

        return 2;
    }
}

static size_t
setup_read_iov(const struct Buffer *buffer, struct iovec *iov, size_t len) {
    if (buffer->len == 0)
        return 0;

    const size_t size = buffer_size(buffer);
    size_t read_len = buffer->len;
    if (len != 0)
        read_len = MIN(len, buffer->len);

    if (buffer->head + read_len <= size) {
        iov[0].iov_base = buffer->buffer + buffer->head;
        iov[0].iov_len = read_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + size);

        return 1;
    } else {
        iov[0].iov_base = buffer->buffer + buffer->head;
        iov[0].iov_len = size - buffer->head;
        iov[1].iov_base = buffer->buffer;
        iov[1].iov_len = read_len - iov[0].iov_len;

        /* assert iov are within bounds, non-zero length and non-overlapping */
        assert(iov[0].iov_len > 0);
        assert((char *)iov[0].iov_base >= buffer->buffer);
        assert((char *)iov[0].iov_base + iov[0].iov_len <= buffer->buffer + size);
        assert(iov[1].iov_len > 0);
        assert((char *)iov[1].iov_base >= buffer->buffer);
        assert((char *)iov[1].iov_base + iov[1].iov_len <= (char *)iov[0].iov_base);

        return 2;
    }
}

static size_t
next_power_of_two(size_t value) {
    if (value == 0)
        return 0;

    value--;

    for (size_t shift = 1; shift < sizeof(size_t) * CHAR_BIT; shift <<= 1)
        value |= value >> shift;

    value++;

    if (value == 0)
        return 0;

    return value;
}

static inline void
advance_write_position(struct Buffer *buffer, size_t offset) {
    buffer->len += offset;
    buffer->rx_bytes += offset;
}

static inline void
advance_read_position(struct Buffer *buffer, size_t offset) {
    buffer->head = (buffer->head + offset) & buffer->size_mask;
    buffer->len -= offset;
    buffer->tx_bytes += offset;
}
