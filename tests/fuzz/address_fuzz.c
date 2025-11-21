#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "address.h"

struct Logger;

static void swallow_log(const char *fmt __attribute__((unused)),
        va_list ap __attribute__((unused))) {}

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
    abort();
}

void err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void notice(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void log_msg(struct Logger *logger __attribute__((unused)),
        int priority __attribute__((unused)),
        const char *fmt __attribute__((unused)), ...) {}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0)
        return 0;

    char *input = malloc(size + 1);
    if (input == NULL)
        return 0;

    memcpy(input, data, size);
    input[size] = '\0';
    for (size_t i = 0; i < size; i++) {
        if (input[i] == '\0')
            input[i] = ' ';
    }

    struct Address *addr = new_address(input);
    if (addr != NULL) {
        char display_buf[ADDRESS_BUFFER_SIZE];
        (void)display_address(addr, display_buf, sizeof(display_buf));
        (void)address_is_hostname(addr);
        (void)address_is_sockaddr(addr);
        (void)address_is_wildcard(addr);
        address_set_port(addr, (uint16_t)size);

        struct Address *copy = copy_address(addr);
        if (copy != NULL) {
            address_set_port(copy, (uint16_t)(size >> 1));
            free(copy);
        }

        free(addr);
    }

    free(input);
    return 0;
}
