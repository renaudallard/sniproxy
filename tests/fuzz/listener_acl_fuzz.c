#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol.h"
#include "listener.h"

struct Logger;

static int stub_protocol_parse_cb(const char *buf __attribute__((unused)),
        size_t len __attribute__((unused)),
        char **host __attribute__((unused))) {
    return -1;
}

static const char http_abort_message[] = "http abort";
static const struct Protocol http_protocol_impl = {
    .name = "http",
    .default_port = 80,
    .parse_packet = stub_protocol_parse_cb,
    .abort_message = http_abort_message,
    .abort_message_len = sizeof(http_abort_message) - 1,
};

static const char tls_abort_message[] = "tls abort";
static const struct Protocol tls_protocol_impl = {
    .name = "tls",
    .default_port = 443,
    .parse_packet = stub_protocol_parse_cb,
    .abort_message = tls_abort_message,
    .abort_message_len = sizeof(tls_abort_message) - 1,
};

/* Mark stub protocol pointers weak so real implementations can override them
 * when linked in, avoiding multiple definition errors. */
const struct Protocol *const http_protocol __attribute__((weak)) = &http_protocol_impl;
const struct Protocol *const tls_protocol __attribute__((weak)) = &tls_protocol_impl;

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

struct Logger *
logger_ref_get(struct Logger *logger) {
    return logger;
}

void
logger_ref_put(struct Logger *logger __attribute__((unused))) {}

int
bind_socket(const struct sockaddr *addr __attribute__((unused)),
        size_t len __attribute__((unused))) {
    errno = EACCES;
    return -1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0)
        return 0;

    struct Listener *listener = new_listener();
    if (listener == NULL)
        return 0;

    SLIST_INIT(&listener->acl_rules);
    listener->acl_mode = (enum ListenerACLMode)((data[0] % 3));

    const uint8_t *ptr = data + 1;
    size_t remaining = (size > 1) ? size - 1 : 0;
    size_t rules = 0;

    while (remaining > 0 && rules < 32) {
        if (remaining < 3)
            break;
        uint8_t selector = *ptr++;
        uint8_t prefix = *ptr++;
        remaining -= 2;

        int family = (selector & 0x1) ? AF_INET6 : AF_INET;
        size_t need = (family == AF_INET) ? 4 : 16;
        if (remaining < need)
            break;

        struct ListenerACLRule *rule = calloc(1, sizeof(*rule));
        if (rule == NULL)
            break;

        rule->family = family;
        if (family == AF_INET) {
            memcpy(&rule->network.in, ptr, 4);
            rule->prefix_len = prefix % 33;
        } else {
            memcpy(&rule->network.in6, ptr, 16);
            rule->prefix_len = prefix % 129;
        }
        ptr += need;
        remaining -= need;

        SLIST_INSERT_HEAD(&listener->acl_rules, rule, entries);
        rules++;
    }

    ptr = data;
    remaining = size;
    while (remaining > 0) {
        if (remaining < 2)
            break;
        uint8_t selector = *ptr++;
        remaining--;
        int family = (selector & 0x1) ? AF_INET6 : AF_INET;
        size_t need = (family == AF_INET) ? 4 : 16;
        if (remaining < need)
            break;

        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        ss.ss_family = family;
        if (family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            memcpy(&sin->sin_addr, ptr, 4);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            memcpy(&sin6->sin6_addr, ptr, 16);
        }
        ptr += need;
        remaining -= need;

        (void)listener_acl_allows(listener, &ss);
    }

    cleanup_listener(listener);
    return 0;
}
