#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ev.h>
#include "config.h"

#define MAX_CONFIG_SIZE (256 * 1024)

static int
write_all(int fd, const uint8_t *data, size_t len) {
    while (len > 0) {
        ssize_t written = write(fd, data, len);
        if (written <= 0)
            return -1;
        data += (size_t)written;
        len -= (size_t)written;
    }
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0 || size > MAX_CONFIG_SIZE)
        return 0;

    char template[] = "/tmp/sniproxy-config-fuzz-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return 0;

    if (write_all(fd, data, size) < 0) {
        close(fd);
        unlink(template);
        return 0;
    }

    /* Ensure file ends with a newline so tokenizer sees final token */
    if (data[size - 1] != '\n') {
        const char nl = '\n';
        (void)write(fd, &nl, 1);
    }
    close(fd);

    struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);
    if (loop == NULL) {
        unlink(template);
        return 0;
    }

    struct Config *config = init_config(template, loop, 1);
    if (config != NULL)
        free_config(config, loop);

    ev_loop_destroy(loop);
    unlink(template);

    return 0;
}
