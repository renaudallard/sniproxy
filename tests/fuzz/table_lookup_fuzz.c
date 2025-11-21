#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "table.h"
#include "backend.h"
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

static void
finalize_backend(struct Table *table, struct Backend **backend_ptr) {
    if (backend_ptr == NULL || *backend_ptr == NULL)
        return;

    struct Backend *backend = *backend_ptr;
    if (valid_backend(backend) > 0) {
        table->use_proxy_header =
                table->use_proxy_header || backend->use_proxy_header;
        add_backend(&table->backends, backend);
    } else {
        free_backend(backend);
    }

    *backend_ptr = NULL;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0)
        return 0;

    struct Table *table = new_table();
    if (table == NULL)
        return 0;

    accept_table_arg(table, "fuzz");

    char *input = malloc(size + 1);
    if (input == NULL) {
        cleanup_table(table);
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    for (size_t i = 0; i < size; i++)
        if (input[i] == '\0')
            input[i] = ' ';

    struct Backend *backend = new_backend();
    size_t backend_tokens = 0;

    char *cursor = input;
    char *token;
    const char *delim = " \t\r\n";

    while ((token = strsep(&cursor, delim)) != NULL) {
        if (*token == '\0')
            continue;

        if (*token == ';') {
            finalize_backend(table, &backend);
            backend = new_backend();
            backend_tokens = 0;
            continue;
        }

        if (backend == NULL) {
            backend = new_backend();
            if (backend == NULL)
                break;
        }

        if (accept_backend_arg(backend, token) <= 0) {
            free_backend(backend);
            backend = new_backend();
        }

        if (++backend_tokens > 512) {
            finalize_backend(table, &backend);
            break;
        }
    }

    finalize_backend(table, &backend);

    if (table != NULL) {
        for (int i = 0; i < 4; i++) {
            size_t offset = (size > 0) ? (data[i % size] % size) : 0;
            size_t len = size - offset;
            if (len > ADDRESS_BUFFER_SIZE - 1)
                len = ADDRESS_BUFFER_SIZE - 1;

            char host[ADDRESS_BUFFER_SIZE];
            memcpy(host, input + offset, len);
            host[len] = '\0';

            struct LookupResult result =
                    table_lookup_server_address(table, host, len);
            if (result.caller_free_address && result.address != NULL)
                free((void *)result.address);
        }
    }

    cleanup_table(table);
    free(input);
    return 0;
}
