#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ares.h>
#include <ares_dns.h>
#include "address.h"
#include "resolv.h"
#include "tests/include/resolver_fuzz.h"

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

int get_resolver_debug(void) {
    return 0;
}

static const int status_map[] = {
    ARES_SUCCESS,
    ARES_ENOTFOUND,
    ARES_ENODATA,
    ARES_EDESTRUCTION,
    ARES_EFORMERR,
    ARES_ESERVFAIL,
    ARES_ECONNREFUSED,
};

static struct ares_addrinfo_node *
build_nodes(const uint8_t *data, size_t size, size_t *offset) {
    const size_t max_nodes = 32;
    struct ares_addrinfo_node *head = NULL;
    struct ares_addrinfo_node *tail = NULL;
    size_t nodes = 0;

    while (*offset < size && nodes < max_nodes) {
        uint8_t ctrl = data[(*offset)++];
        int node_family = (ctrl & 0x1u) ? AF_INET6 : AF_INET;
        size_t raw_len = node_family == AF_INET ? 4u : 16u;
        if (*offset + raw_len > size)
            break;

        struct sockaddr *addr = NULL;
        socklen_t addr_len = 0;
        if ((ctrl & 0x2u) == 0) {
            if (node_family == AF_INET) {
                struct sockaddr_in *sin = calloc(1, sizeof(*sin));
                if (sin == NULL)
                    break;
                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, data + *offset, 4);
                sin->sin_port = htons((uint16_t)((ctrl << 8) | data[*offset]));
                addr = (struct sockaddr *)sin;
                addr_len = (socklen_t)sizeof(*sin);
            } else {
                struct sockaddr_in6 *sin6 = calloc(1, sizeof(*sin6));
                if (sin6 == NULL)
                    break;
                sin6->sin6_family = AF_INET6;
                memcpy(&sin6->sin6_addr, data + *offset, 16);
                sin6->sin6_port = htons((uint16_t)((ctrl << 8) | data[*offset]));
                addr = (struct sockaddr *)sin6;
                addr_len = (socklen_t)sizeof(*sin6);
            }
        }

        struct ares_addrinfo_node *node = calloc(1, sizeof(*node));
        if (node == NULL) {
            free(addr);
            break;
        }

        node->ai_family = node_family;
        if ((ctrl & 0x8u) != 0 && addr != NULL) {
            free(addr);
            addr = NULL;
        }
        node->ai_addr = addr;
        node->ai_addrlen = (ctrl & 0x4u) ? (socklen_t)(addr_len / 2) : addr_len;

        if (head == NULL)
            head = node;
        else
            tail->ai_next = node;
        tail = node;
        nodes++;
        *offset += raw_len;
    }

    return head;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size < 4)
        return 0;

    struct ResolverChildQuery *query = resolver_fuzz_query_create();
    if (query == NULL)
        return 0;

    int status = status_map[data[0] % (sizeof(status_map) / sizeof(status_map[0]))];
    int family = (data[1] & 0x1u) ? AF_INET6 : AF_INET;
    int flags = data[2];
    resolver_fuzz_query_configure(query,
            flags & 0x1,
            (flags >> 1) & 0x1,
            (flags >> 2) & 0x1,
            (flags >> 3) & 0x1);
    resolver_fuzz_query_set_id(query, data[3]);

    size_t offset = 4;
    struct ares_addrinfo *result = calloc(1, sizeof(*result));
    if (result == NULL) {
        resolver_fuzz_query_free(query);
        return 0;
    }

    result->nodes = build_nodes(data, size, &offset);

    resolver_fuzz_handle_addrinfo(query, status, result, family);

    resolver_fuzz_query_free(query);
    return 0;
}
