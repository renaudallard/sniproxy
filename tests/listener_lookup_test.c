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

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "listener.h"

struct Address {
    uint16_t port;
    int is_wildcard;
    int is_sockaddr;
};

static struct Address backend_address = {0, 0, 0};
static struct Address listener_address = {1234, 0, 0};
static struct Address fallback_address = {5678, 0, 0};
static uint16_t last_set_port = 0;

int address_is_wildcard(const struct Address *addr) {
    return addr != NULL && addr->is_wildcard;
}

int address_is_sockaddr(const struct Address *addr) {
    return addr != NULL && addr->is_sockaddr;
}

uint16_t address_port(const struct Address *addr) {
    return addr != NULL ? addr->port : 0;
}

void address_set_port(struct Address *addr, uint16_t port) {
    last_set_port = port;
    if (addr != NULL)
        addr->port = port;
}

struct Address *copy_address(const struct Address *addr) {
    (void)addr;
    errno = ENOMEM;
    return NULL;
}

struct Address *new_address(const char *name) {
    (void)name;
    return NULL;
}

struct Address *new_address_sa(const struct sockaddr *sa, socklen_t len) {
    (void)sa;
    (void)len;
    return NULL;
}

size_t address_len(const struct Address *addr) {
    (void)addr;
    return sizeof(struct Address);
}

int address_compare(const struct Address *addr_1, const struct Address *addr_2) {
    if (addr_1 == addr_2)
        return 0;
    return addr_1 < addr_2 ? -1 : 1;
}

int address_is_hostname(const struct Address *addr) {
    (void)addr;
    return 0;
}

const char *address_hostname(const struct Address *addr) {
    (void)addr;
    return NULL;
}

const struct sockaddr *address_sa(const struct Address *addr) {
    (void)addr;
    return NULL;
}

socklen_t address_sa_len(const struct Address *addr) {
    (void)addr;
    return 0;
}

int address_set_port_str(struct Address *addr, const char *str) {
    (void)addr;
    (void)str;
    return 0;
}

const char *display_address(const struct Address *addr, char *buffer, size_t buffer_len) {
    (void)addr;
    (void)buffer;
    (void)buffer_len;
    return NULL;
}

const char *display_sockaddr(const void *sa, char *buffer, size_t buffer_len) {
    (void)sa;
    (void)buffer;
    (void)buffer_len;
    return NULL;
}

int is_numeric(const char *s) {
    (void)s;
    return 0;
}

struct Logger {};
struct Logger *logger_ref_get(struct Logger *logger) {
    return logger;
}

void logger_ref_put(struct Logger *logger) {
    (void)logger;
}

void err(const char *fmt, ...) {
    (void)fmt;
}

void warn(const char *fmt, ...) {
    (void)fmt;
}

void notice(const char *fmt, ...) {
    (void)fmt;
}

void info(const char *fmt, ...) {
    (void)fmt;
}

void debug(const char *fmt, ...) {
    (void)fmt;
}

void fatal(const char *fmt, ...) {
    (void)fmt;
}

struct Protocol { const char *name; };
const struct Protocol *const http_protocol = NULL;
const struct Protocol *const tls_protocol = NULL;

struct Table *table_lookup(const struct Table_head *tables, const char *name) {
    (void)tables;
    (void)name;
    return NULL;
}

void init_table(struct Table *table) {
    (void)table;
}

struct Table *table_ref_get(struct Table *table) {
    return table;
}

void table_ref_put(struct Table *table) {
    (void)table;
}

int bind_socket(const struct sockaddr *addr, size_t len) {
    (void)addr;
    (void)len;
    return -1;
}

static struct LookupResult stub_lookup_result;

struct LookupResult table_lookup_server_address(const struct Table *table, const char *name,
        size_t name_len, enum TableLookupTarget target) {
    assert(table != NULL);
    (void)name;
    (void)name_len;
    (void)target;
    return stub_lookup_result;
}

int main(void) {
    struct Listener listener = {0};
    listener.address = &listener_address;
    listener.fallback_address = &fallback_address;
    listener.fallback_use_proxy_header = 1;

    backend_address.port = 0;
    backend_address.is_wildcard = 0;
    backend_address.is_sockaddr = 0;

    stub_lookup_result.address = &backend_address;
    stub_lookup_result.use_proxy_header = 0;
    stub_lookup_result.caller_free_address = 0;
    stub_lookup_result.resolved_target = TABLE_LOOKUP_TARGET_DEFAULT;

    last_set_port = 0;

    const char hostname[] = "example.com";
    struct LookupResult result = listener_lookup_server_address(&listener, hostname, strlen(hostname));

    assert(result.address == listener.fallback_address);
    assert(result.caller_free_address == 0);
    assert(result.use_proxy_header == listener.fallback_use_proxy_header);
    assert(result.resolved_target == TABLE_LOOKUP_TARGET_DEFAULT);
    assert(last_set_port == 0);

    /* When the listener has no associated table we should fall back without
     * attempting a lookup. */
    listener.table = NULL;

    result = listener_lookup_server_address(&listener, hostname, strlen(hostname));
    assert(result.address == listener.fallback_address);
    assert(result.caller_free_address == 0);
    assert(result.use_proxy_header == listener.fallback_use_proxy_header);
    assert(result.resolved_target == TABLE_LOOKUP_TARGET_DEFAULT);

    return 0;
}
