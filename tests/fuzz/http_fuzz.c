#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include "protocol.h"
#include "http.h"

struct Logger;

/* Minimal logger stubs so we do not need the full logging subsystem */
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *hostname = NULL;

    if (http_protocol != NULL && http_protocol->parse_packet != NULL)
        http_protocol->parse_packet((const char *)data, size, &hostname);

    free(hostname);
    return 0;
}
