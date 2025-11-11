/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include "table.h"
#include "backend.h"
#include "address.h"
#include "logger.h"


static void free_table(struct Table *);

static inline uint32_t table_hash_hostname(const char *name, size_t len);
static struct Backend *table_cache_probe(const struct Table *, const char *, size_t, uint32_t);
static void table_cache_store(struct Table *, const char *, size_t, uint32_t, struct Backend *);
static void table_cache_clear(struct Table *);


static inline struct Backend *
table_lookup_backend(const struct Table *table, const char *name, size_t name_len) {
    return lookup_backend(&table->backends, name, name_len);
}

static inline void __attribute__((unused))
remove_table_backend(struct Table *table, struct Backend *backend) {
    remove_backend(&table->backends, backend);
}

static inline uint32_t
table_hash_hostname(const char *name, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)name[i];
        hash *= 16777619u;
    }
    return hash;
}

static struct Backend *
table_cache_probe(const struct Table *table, const char *name, size_t len, uint32_t hash) {
    if (table == NULL || len == 0 || len > TABLE_CACHE_MAX_NAME_LEN)
        return NULL;

    const struct TableCacheEntry *entry = &table->cache[hash & (TABLE_CACHE_SIZE - 1u)];
    if (entry->backend == NULL)
        return NULL;
    if (entry->generation != table->cache_generation)
        return NULL;
    if (entry->hash != hash || entry->name_len != len)
        return NULL;
    if (memcmp(entry->name, name, len) != 0)
        return NULL;
    return entry->backend;
}

static void
table_cache_store(struct Table *table, const char *name, size_t len, uint32_t hash, struct Backend *backend) {
    if (table == NULL || backend == NULL || len == 0 || len > TABLE_CACHE_MAX_NAME_LEN)
        return;

    struct TableCacheEntry *entry = &table->cache[hash & (TABLE_CACHE_SIZE - 1u)];
    entry->hash = hash;
    entry->name_len = (uint16_t)len;
    entry->generation = table->cache_generation;
    memcpy(entry->name, name, len);
    entry->name[len] = '\0';
    entry->backend = backend;
}

static void
table_cache_clear(struct Table *table) {
    if (table == NULL)
        return;

    table->cache_generation++;
    if (table->cache_generation == 0)
        table->cache_generation = 1;

    memset(table->cache, 0, sizeof(table->cache));
}


struct Table *
new_table(void) {
    struct Table *table;

    table = calloc(1, sizeof(struct Table));
    if (table == NULL) {
        err("malloc: %s", strerror(errno));
        return NULL;
    }

    STAILQ_INIT(&table->backends);
    table->cache_generation = 1;
    memset(table->cache, 0, sizeof(table->cache));

    return table;
}

int
accept_table_arg(struct Table *table, const char *arg) {
    if (table->name == NULL) {
        table->name = strdup(arg);
        if (table->name == NULL) {
            err("strdup: %s", strerror(errno));
            return -1;
        }
    } else {
        err("Unexpected table argument: %s", arg);
        return -1;
    }

    return 1;
}


void
add_table(struct Table_head *tables, struct Table *table) {
    table_ref_get(table);
    SLIST_INSERT_HEAD(tables, table, entries);
}

int
valid_table(struct Table *table) {
    if (table == NULL) {
        err("Invalid table definition");
        return 0;
    }

    const char *table_name = table->name != NULL ? table->name : "(default)";

    if (STAILQ_EMPTY(&table->backends)) {
        err("Table \"%s\" does not define any backends", table_name);
        return 0;
    }

    struct Backend *backend;
    STAILQ_FOREACH(backend, &table->backends, entries) {
        if (!valid_backend(backend)) {
            err("Table \"%s\" contains an invalid backend definition", table_name);
            return 0;
        }
    }

    return 1;
}

void init_table(struct Table *table) {
    struct Backend *iter = STAILQ_FIRST(&table->backends);

    while (iter != NULL) {
        struct Backend *next = STAILQ_NEXT(iter, entries);

        if (!init_backend(iter)) {
            const char *pattern = iter->pattern != NULL ? iter->pattern : "(null)";
            char address[ADDRESS_BUFFER_SIZE];
            const char *address_str = display_address(iter->address, address,
                    sizeof(address));

            if (address_str != NULL)
                err("Removing backend \"%s\" %s due to failed regex compilation",
                        pattern, address_str);
            else
                err("Removing backend \"%s\" due to failed regex compilation",
                        pattern);

            remove_backend(&table->backends, iter);
        }

        iter = next;
    }
    table_cache_clear(table);
}

void
free_tables(struct Table_head *tables) {
    struct Table *iter;

    while ((iter = SLIST_FIRST(tables)) != NULL) {
        SLIST_REMOVE_HEAD(tables, entries);
        table_ref_put(iter);
    }
}

struct Table *
table_lookup(const struct Table_head *tables, const char *name) {
    struct Table *iter = SLIST_FIRST(tables);

    while (iter != NULL) {
        if (iter->name == NULL && name == NULL) {
            return iter;
        } else if (iter->name != NULL && name != NULL &&
                strcmp(iter->name, name) == 0) {
            return iter;
        }
        iter = SLIST_NEXT(iter, entries);
    }

    return NULL;
}

void
remove_table(struct Table_head *tables, struct Table *table) {
    SLIST_REMOVE(tables, table, Table, entries);
    table_ref_put(table);
}

struct LookupResult
table_lookup_server_address(const struct Table *table, const char *name, size_t name_len) {
    struct Backend *backend = NULL;
    uint32_t hash = 0;
    int cacheable = (table != NULL && name != NULL && name_len > 0 &&
            name_len <= TABLE_CACHE_MAX_NAME_LEN);

    if (cacheable) {
        hash = table_hash_hostname(name, name_len);
        backend = table_cache_probe(table, name, name_len, hash);
    }

    if (backend == NULL) {
        backend = table_lookup_backend(table, name, name_len);
        if (backend == NULL) {
            info("No match found for %.*s", (int)name_len, name ? name : "");
            return (struct LookupResult){.address = NULL};
        }
        if (cacheable)
            table_cache_store((struct Table *)table, name, name_len, hash, backend);
    }

    return (struct LookupResult){.address = backend->address,
                                 .use_proxy_header = backend->use_proxy_header};
}

void
reload_tables(struct Table_head *tables, struct Table_head *new_tables) {
    struct Table *iter;

    /* Remove unused tables which were removed from the new configuration */
    /* Unused elements at the beginning of the list */
    while ((iter = SLIST_FIRST(tables)) != NULL &&
            table_lookup(new_tables, SLIST_FIRST(tables)->name) == NULL) {
        SLIST_REMOVE_HEAD(tables, entries);
        table_ref_put(iter);
    }
    /* Remove elements following first used element */
    SLIST_FOREACH(iter, tables, entries) {
        if (SLIST_NEXT(iter, entries) != NULL &&
                table_lookup(new_tables,
                        SLIST_NEXT(iter, entries)->name) == NULL) {
            struct Table *temp = SLIST_NEXT(iter, entries);
            /* SLIST remove next */
            SLIST_NEXT(iter, entries) = SLIST_NEXT(temp, entries);
            table_ref_put(temp);
        }
    }


    while ((iter = SLIST_FIRST(new_tables)) != NULL) {
        SLIST_REMOVE_HEAD(new_tables, entries);

        /* Initialize table regular expressions */
        init_table(iter);

        struct Table *existing = table_lookup(tables, iter->name);
        if (existing) {
            /* Swap table contents */
            struct Backend_head temp = existing->backends;
            existing->backends = iter->backends;
            iter->backends = temp;
        } else {
            add_table(tables, iter);
        }
        table_ref_put(iter);
    }
}

void
print_table_config(FILE *file, struct Table *table) {
    struct Backend *backend = STAILQ_FIRST(&table->backends);

    if (table->name == NULL)
        fprintf(file, "table {\n");
    else
        fprintf(file, "table %s {\n", table->name);

    while (backend != NULL) {
        print_backend_config(file, backend);
        backend = STAILQ_NEXT(backend, entries);
    }
    fprintf(file, "}\n\n");
}

static void
free_table(struct Table *table) {
    struct Backend *iter;

    if (table == NULL)
        return;

    while ((iter = STAILQ_FIRST(&table->backends)) != NULL)
        remove_backend(&table->backends, iter);

    free(table->name);
    free(table);
}

void
table_ref_put(struct Table *table) {
    if (table == NULL)
        return;

    assert(table->reference_count > 0);
    table->reference_count--;
    if (table->reference_count == 0)
        free_table(table);
}

struct Table *
table_ref_get(struct Table *table) {
    table->reference_count++;
    return table;
}
