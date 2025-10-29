#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ev.h>
#include "buffer.h"

static void test1(void) {
    struct Buffer *buffer;
    char input[] = "This is a test.";
    char output[sizeof(input)];
    int len, i;

    buffer = new_buffer(256, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, input, sizeof(input));
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* second peek to ensure the first didn't permute the state of the buffer */
    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    /* test pop */
    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == 0);

    free_buffer(buffer);
}

static void test2(void) {
    struct Buffer *buffer;
    char input[] = "Testing wrap around behaviour.";
    char output[sizeof(input)];
    int len, i = 0;

    buffer = new_buffer(256, EV_DEFAULT);
    assert(buffer != NULL);

    while (i < 236) {
        len = buffer_push(buffer, input, sizeof(input));
        assert(len == sizeof(input));

        i += len;
    }

    while (len) {
        len = buffer_pop(buffer, output, sizeof(output));
    }

    len = buffer_push(buffer, input, sizeof(input));
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    len = buffer_push(buffer, input, sizeof(input));
    assert(len == sizeof(input));


    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    free_buffer(buffer);
}

static void test3(void) {
    struct Buffer *buffer;
    char input[] = "Test buffer resizing.";
    char output[sizeof(input)];
    int len, i;

    buffer = new_buffer(256, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, input, sizeof(input));
    assert(len == sizeof(input));

    /* Test resizing to too small of a buffer size */
    len = buffer_resize(buffer, 8);
    assert(len == -1);


    buffer_resize(buffer, 32);
    assert(buffer_room(buffer) == 32 - sizeof(input));

    len = buffer_peek(buffer, output, sizeof(output));
    assert(len == sizeof(input));

    for (i = 0; i < len; i++)
        assert(input[i] == output[i]);

    free_buffer(buffer);
}

static void test4(void) {
    struct Buffer *buffer;
    int read_fd, write_fd;

    buffer = new_buffer(16384, EV_DEFAULT);

    read_fd = open("/dev/zero", O_RDONLY);
    if (read_fd < 0) {
        perror("open:");
        exit(1);
    }

    write_fd = open("/dev/null", O_WRONLY);
    if (write_fd < 0) {
        perror("open:");
        exit(1);
    }

    while (buffer->tx_bytes < 65536) {
        buffer_read(buffer, read_fd);
        buffer_write(buffer, write_fd);
    }

    free_buffer(buffer);
}

static void test_buffer_coalesce(void) {
    struct Buffer *buffer;
    char input[] = "Test buffer resizing.";
    char output[sizeof(input)];
    int len;

    buffer = new_buffer(16384, EV_DEFAULT);
    len = buffer_push(buffer, input, sizeof(input));
    assert(len == sizeof(input));

    len = buffer_pop(buffer, output, sizeof(output));
    assert(len == sizeof(output));
    assert(buffer_len(buffer) == 0);
    assert(buffer->head != 0);

    len = buffer_coalesce(buffer, NULL);
    assert(len == 0);
}

static void test_buffer_reserve_and_expand(void) {
    struct Buffer *buffer;
    char payload[8] = {0};
    char extra[32];
    size_t len;

    buffer = new_buffer(8, EV_DEFAULT);
    assert(buffer != NULL);

    len = buffer_push(buffer, payload, sizeof(payload));
    assert(len == sizeof(payload));

    assert(buffer_reserve(buffer, sizeof(payload)) == 0);
    assert(buffer_room(buffer) >= sizeof(payload));

    for (size_t i = 0; i < sizeof(extra); i++)
        extra[i] = (char)i;

    len = buffer_push(buffer, extra, sizeof(extra));
    assert(len == sizeof(extra));
    assert(buffer_len(buffer) == sizeof(payload) + sizeof(extra));

    free_buffer(buffer);
}

static void test_buffer_reserve_overflow(void) {
    struct Buffer *buffer = new_buffer(1024, EV_DEFAULT);
    assert(buffer != NULL);

    assert(buffer_reserve(buffer, SIZE_MAX) == -1);

    free_buffer(buffer);
}

static void test_buffer_maybe_shrink(void) {
    struct Buffer *buffer = new_buffer(16, EV_DEFAULT);
    char payload[128] = {0};

    assert(buffer != NULL);

    assert(buffer_push(buffer, payload, sizeof(payload)) == sizeof(payload));
    assert(buffer_size(buffer) >= sizeof(payload));

    assert(buffer_pop(buffer, NULL, sizeof(payload)) == sizeof(payload));
    assert(buffer_len(buffer) == 0);

    assert(buffer_maybe_shrink(buffer) == 0);
    assert(buffer_size(buffer) == 16);

    free_buffer(buffer);
}

int main(void) {
    test1();

    test2();

    test3();

    test4();

    test_buffer_coalesce();

    test_buffer_reserve_and_expand();

    test_buffer_reserve_overflow();

    test_buffer_maybe_shrink();
}
