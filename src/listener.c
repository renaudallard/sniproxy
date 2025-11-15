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
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h> /* offsetof */
#include <strings.h> /* strcasecmp() */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
#include "address.h"
#include "listener.h"
#include "logger.h"
#include "binder.h"
#include "protocol.h"
#include "tls.h"
#include "http.h"
#include "fd_util.h"

#define LISTENER_ACCEPT_MAX_BATCH 64

static void close_listener(struct ev_loop *, struct Listener *);
static void accept_cb(struct ev_loop *, struct ev_io *, int);
static void backoff_timer_cb(struct ev_loop *, struct ev_timer *, int);
static int init_listener(struct Listener *, const struct Table_head *, struct ev_loop *);
static void listener_update(struct Listener *, struct Listener *,  const struct Table_head *);
static void free_listener(struct Listener *);
static int parse_boolean(const char *);


static void listener_acl_clear(struct Listener *);
static void listener_acl_move(struct Listener *, struct Listener *);
static int listener_acl_contains(const struct Listener *, const struct sockaddr_storage *);
static int listener_acl_rule_match_v4(const struct ListenerACLRule *, const struct in_addr *);
static int listener_acl_rule_match_v6(const struct ListenerACLRule *, const struct in6_addr *);
static const char *listener_acl_rule_to_string(const struct ListenerACLRule *, char *, size_t);


static int
parse_boolean(const char *boolean) {
    const char *boolean_true[] = {
        "yes",
        "true",
        "on",
    };

    const char *boolean_false[] = {
        "no",
        "false",
        "off",
    };

    for (size_t i = 0; i < sizeof(boolean_true) / sizeof(boolean_true[0]); i++)
        if (strcasecmp(boolean, boolean_true[i]) == 0)
            return 1;

    for (size_t i = 0; i < sizeof(boolean_false) / sizeof(boolean_false[0]); i++)
        if (strcasecmp(boolean, boolean_false[i]) == 0)
            return 0;

    err("Unable to parse '%s' as a boolean value", boolean);

    return -1;
}

static void
listener_acl_clear(struct Listener *listener) {
    struct ListenerACLRule *rule;

    if (listener == NULL)
        return;

    while ((rule = SLIST_FIRST(&listener->acl_rules)) != NULL) {
        SLIST_REMOVE_HEAD(&listener->acl_rules, entries);
        free(rule);
    }

    listener->acl_mode = LISTENER_ACL_MODE_DISABLED;
}

static void
listener_acl_move(struct Listener *dst, struct Listener *src) {
    if (dst == NULL || src == NULL)
        return;

    listener_acl_clear(dst);
    dst->acl_mode = src->acl_mode;
    dst->acl_rules = src->acl_rules;
    SLIST_INIT(&src->acl_rules);
    src->acl_mode = LISTENER_ACL_MODE_DISABLED;
}

static int
listener_acl_rule_match_v4(const struct ListenerACLRule *rule, const struct in_addr *addr) {
    if (rule == NULL || addr == NULL)
        return 0;

    if (rule->prefix_len == 0)
        return 1;

    uint32_t mask = rule->prefix_len == 32 ? UINT32_MAX : (~0u << (32 - rule->prefix_len));
    uint32_t addr_val = ntohl(addr->s_addr);
    uint32_t net_val = ntohl(rule->network.in.s_addr);

    return (addr_val & mask) == (net_val & mask);
}

static int
listener_acl_rule_match_v6(const struct ListenerACLRule *rule, const struct in6_addr *addr) {
    if (rule == NULL || addr == NULL)
        return 0;

    if (rule->prefix_len == 0)
        return 1;

    unsigned full_bytes = rule->prefix_len / 8;
    unsigned remaining_bits = rule->prefix_len % 8;

    if (full_bytes > 0) {
        if (memcmp(addr->s6_addr, rule->network.in6.s6_addr, full_bytes) != 0)
            return 0;
    }

    if (remaining_bits > 0 && full_bytes < sizeof(rule->network.in6.s6_addr)) {
        uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
        if ((addr->s6_addr[full_bytes] & mask) !=
                (rule->network.in6.s6_addr[full_bytes] & mask))
            return 0;
    }

    return 1;
}

static int
listener_acl_contains(const struct Listener *listener, const struct sockaddr_storage *addr) {
    const struct ListenerACLRule *rule;

    if (listener == NULL || addr == NULL)
        return 0;

    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        SLIST_FOREACH(rule, &listener->acl_rules, entries) {
            if (rule->family == AF_INET &&
                    listener_acl_rule_match_v4(rule, &sin->sin_addr))
                return 1;
        }
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            struct in_addr v4;
            memcpy(&v4.s_addr, &sin6->sin6_addr.s6_addr[12], sizeof(v4.s_addr));
            SLIST_FOREACH(rule, &listener->acl_rules, entries) {
                if (rule->family == AF_INET &&
                        listener_acl_rule_match_v4(rule, &v4))
                    return 1;
            }
        } else {
            SLIST_FOREACH(rule, &listener->acl_rules, entries) {
                if (rule->family == AF_INET6 &&
                        listener_acl_rule_match_v6(rule, &sin6->sin6_addr))
                    return 1;
            }
        }
    }

    return 0;
}

static const char *
listener_acl_rule_to_string(const struct ListenerACLRule *rule, char *buffer, size_t len) {
    const void *addr = NULL;

    if (buffer == NULL || len == 0)
        return "(invalid)";

    if (rule == NULL) {
        snprintf(buffer, len, "(invalid)");
        return buffer;
    }

    if (rule->family == AF_INET)
        addr = &rule->network.in;
    else if (rule->family == AF_INET6)
        addr = &rule->network.in6;
    else {
        snprintf(buffer, len, "(invalid)");
        return buffer;
    }

    if (inet_ntop(rule->family, addr, buffer, len) == NULL) {
        snprintf(buffer, len, "(invalid)");
        return buffer;
    }

    size_t used = strlen(buffer);
    if (used + 5 >= len) {
        snprintf(buffer, len, "(invalid)");
        return buffer;
    }

    snprintf(buffer + used, len - used, "/%u", rule->prefix_len);

    return buffer;
}

/*
 * Initialize each listener.
 */
void
init_listeners(struct Listener_head *listeners,
        const struct Table_head *tables, struct ev_loop *loop) {
    struct Listener *iter = SLIST_FIRST(listeners);
    char address[ADDRESS_BUFFER_SIZE];

    while (iter != NULL) {
        if (init_listener(iter, tables, loop) < 0) {
            err("Failed to initialize listener %s",
                    display_address(iter->address, address, sizeof(address)));
            exit(1);
        }
        iter = SLIST_NEXT(iter, entries);
    }
}

void
listeners_reload(struct Listener_head *existing_listeners,
        struct Listener_head *new_listeners,
        const struct Table_head *tables, struct ev_loop *loop) {
    struct Listener *iter_existing = SLIST_FIRST(existing_listeners);
    struct Listener *iter_new = SLIST_FIRST(new_listeners);

    while (iter_existing != NULL || iter_new != NULL) {
        int compare_result;
        char address[ADDRESS_BUFFER_SIZE];

        if (iter_existing == NULL)
            compare_result = 1;
        else if (iter_new == NULL)
            compare_result = -1;
        else
            compare_result = address_compare(iter_existing->address, iter_new->address);

        if (compare_result > 0) {
            struct Listener *new_listener = iter_new;
            iter_new = SLIST_NEXT(iter_new, entries);

            notice("Listener %s added.",
                    display_address(new_listener->address,
                            address, sizeof(address)));

            /* Using SLIST_REMOVE rather than remove_listener to defer
             * decrementing reference count until after adding to the running
             * config */
            SLIST_REMOVE(new_listeners, new_listener, Listener, entries);
            add_listener(existing_listeners, new_listener);
            init_listener(new_listener, tables, loop);

            /* -1 for removing from new_listeners */
            listener_ref_put(new_listener);
        } else if (compare_result == 0) {
            notice ("Listener %s updated.",
                    display_address(iter_existing->address,
                            address, sizeof(address)));

            listener_update(iter_existing, iter_new, tables);

            iter_existing = SLIST_NEXT(iter_existing, entries);
            iter_new = SLIST_NEXT(iter_new, entries);
        } else {
            struct Listener *removed_listener = iter_existing;
            iter_existing = SLIST_NEXT(iter_existing, entries);

            notice("Listener %s removed.",
                    display_address(removed_listener->address,
                            address, sizeof(address)));

            remove_listener(existing_listeners, removed_listener, loop);
        }
    }
}

/*
 * Copy contents of new_listener into existing listener
 */
static void
listener_update(struct Listener *existing_listener, struct Listener *new_listener, const struct Table_head *tables) {
    assert(existing_listener != NULL);
    assert(new_listener != NULL);
    assert(address_compare(existing_listener->address, new_listener->address) == 0);

    free(existing_listener->fallback_address);
    existing_listener->fallback_address = new_listener->fallback_address;
    new_listener->fallback_address = NULL;
    existing_listener->fallback_use_proxy_header =
            new_listener->fallback_use_proxy_header;

    free(existing_listener->source_address);
    existing_listener->source_address = new_listener->source_address;
    new_listener->source_address = NULL;
    existing_listener->transparent_proxy = new_listener->transparent_proxy;

    existing_listener->protocol = new_listener->protocol;

    free(existing_listener->table_name);
    existing_listener->table_name = new_listener->table_name;
    new_listener->table_name = NULL;

    logger_ref_put(existing_listener->access_log);
    existing_listener->access_log = logger_ref_get(new_listener->access_log);

    existing_listener->log_bad_requests = new_listener->log_bad_requests;
    existing_listener->reuseport = new_listener->reuseport;
    existing_listener->ipv6_v6only = new_listener->ipv6_v6only;

    listener_acl_move(existing_listener, new_listener);

    struct Table *new_table =
            table_lookup(tables, existing_listener->table_name);

    if (new_table != NULL) {
        init_table(new_table);

        table_ref_put(existing_listener->table);
        existing_listener->table = table_ref_get(new_table);

        table_ref_put(new_listener->table);
        new_listener->table = NULL;
    }
}

struct Listener *
new_listener(void) {
    struct Listener *listener = calloc(1, sizeof(struct Listener));
    if (listener == NULL) {
        err("calloc");
        return NULL;
    }

    listener->address = NULL;
    listener->fallback_address = NULL;
    listener->source_address = NULL;
    listener->protocol = tls_protocol;
    listener->table_name = NULL;
    listener->access_log = NULL;
    listener->log_bad_requests = 0;
    listener->reuseport = 0;
    listener->ipv6_v6only = 0;
    listener->transparent_proxy = 0;
    listener->fallback_use_proxy_header = 0;
    listener->acl_mode = LISTENER_ACL_MODE_DISABLED;
    SLIST_INIT(&listener->acl_rules);
    listener->reference_count = 0;
    /* Initializes sock fd to negative sentinel value to indicate watchers
     * are not active */
    ev_io_init(&listener->watcher, accept_cb, -1, EV_READ);
    ev_timer_init(&listener->backoff_timer, backoff_timer_cb, 0.0, 0.0);
    listener->table = NULL;

    return listener;
}

int
accept_listener_arg(struct Listener *listener, const char *arg) {
    if (listener->address == NULL && !is_numeric(arg)) {
        listener->address = new_address(arg);

        if (listener->address == NULL ||
                !address_is_sockaddr(listener->address)) {
            err("Invalid listener argument %s", arg);
            return -1;
        }
    } else if (listener->address == NULL && is_numeric(arg)) {
        listener->address = new_address("[::]");

        if (listener->address == NULL ||
                !address_is_sockaddr(listener->address)) {
            err("Unable to initialize default address");
            return -1;
        }
        if (!address_set_port_str(listener->address, arg)) {
            err("Invalid port %s", arg);
            return -1;
        }
    } else if (address_port(listener->address) == 0 && is_numeric(arg)) {
        if (!address_set_port_str(listener->address, arg)) {
            err("Invalid port %s", arg);
            return -1;
        }
    } else {
        err("Invalid listener argument %s", arg);
    }

    return 1;
}

int
accept_listener_table_name(struct Listener *listener, const char *table_name) {
    if (listener->table_name != NULL) {
        err("Duplicate table: %s", table_name);
        return 0;
    }
    listener->table_name = strdup(table_name);
    if (listener->table_name == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

int
accept_listener_protocol(struct Listener *listener, const char *protocol) {
    if (strncasecmp(protocol, http_protocol->name, strlen(protocol)) == 0)
        listener->protocol = http_protocol;
    else
        listener->protocol = tls_protocol;

    if (address_port(listener->address) == 0)
        address_set_port(listener->address, listener->protocol->default_port);

    return 1;
}

int
accept_listener_reuseport(struct Listener *listener, const char *reuseport) {
    listener->reuseport = parse_boolean(reuseport);
    if (listener->reuseport == -1) {
        return 0;
    }

#ifndef SO_REUSEPORT
    if (listener->reuseport == 1) {
        err("Reuseport not supported in this build");
        return 0;
    }
#endif

    return 1;
}

int
accept_listener_ipv6_v6only(struct Listener *listener, const char *ipv6_v6only) {
    listener->ipv6_v6only = parse_boolean(ipv6_v6only);
    if (listener->ipv6_v6only == -1) {
        return 0;
    }

#ifndef IPV6_V6ONLY
    if (listener->ipv6_v6only == 1) {
        err("IPV6_V6ONLY not supported in this build");
        return 0;
    }
#endif

    return 1;
}

int
accept_listener_fallback_address(struct Listener *listener, const char *fallback) {
    if (listener->fallback_address == NULL) {
        struct Address *fallback_address = new_address(fallback);
        if (fallback_address == NULL) {
            err("Unable to parse fallback address: %s", fallback);
            return 0;
        } else if (address_is_sockaddr(fallback_address)) {
            listener->fallback_address = fallback_address;
            return 1;
        } else if (address_is_hostname(fallback_address)) {
            warn("Using hostname as fallback address is strongly discouraged");
            listener->fallback_address = fallback_address;
            return 1;
        } else if (address_is_wildcard(fallback_address)) {
            /* The wildcard functionality requires successfully parsing the
             * hostname from the client's request, if we couldn't find the
             * hostname and are using a fallback address it doesn't make
             * much sense to configure it as a wildcard. */
            err("Wildcard address prohibited as fallback address");
            free(fallback_address);
            return 0;
        } else {
            fatal("Unexpected fallback address type");
            return 0;
        }
    } else if (strcasecmp("proxy", fallback) == 0 &&
            listener->fallback_use_proxy_header == 0) {
        listener->fallback_use_proxy_header = 1;
        return 1;
    } else {
        err("Unexpected fallback argument: %s", fallback);
        return 0;
    }
}

int
accept_listener_source_address(struct Listener *listener, const char *source) {
    if (listener->source_address != NULL || listener->transparent_proxy) {
        err("Duplicate source address: %s", source);
        return 0;
    }

    if (strcasecmp("client", source) == 0) {
#ifdef IP_TRANSPARENT
        listener->transparent_proxy = 1;
        return 1;
#else
        err("Transparent proxy not supported on this platform.");
        return 0;
#endif
    }

    listener->source_address = new_address(source);
    if (listener->source_address == NULL) {
        err("Unable to parse source address: %s", source);
        return 0;
    }
    if (!address_is_sockaddr(listener->source_address)) {
        err("Only source socket addresses permitted");
        free(listener->source_address);
        listener->source_address = NULL;
        return 0;
    }
    if (address_port(listener->source_address) != 0) {
        char address[ADDRESS_BUFFER_SIZE];
        err("Source address on listener %s set to non zero port, "
                "this prevents multiple connection to each backend server.",
                display_address(listener->address, address, sizeof(address)));
    }

    return 1;
}

int
accept_listener_bad_request_action(struct Listener *listener, const char *action) {
    if (strncmp("log", action, strlen(action)) == 0) {
        listener->log_bad_requests = 1;
    }

    return 1;
}

/*
 * Insert an additional listener in to the sorted list of listeners
 */
void
add_listener(struct Listener_head *listeners, struct Listener *listener) {
    assert(listeners != NULL);
    assert(listener != NULL);
    assert(listener->address != NULL);
    listener_ref_get(listener);

    if (SLIST_FIRST(listeners) == NULL ||
            address_compare(listener->address, SLIST_FIRST(listeners)->address) < 0) {
        SLIST_INSERT_HEAD(listeners, listener, entries);
        return;
    }

    struct Listener *iter;
    SLIST_FOREACH(iter, listeners, entries) {
        if (SLIST_NEXT(iter, entries) == NULL ||
                address_compare(listener->address, SLIST_NEXT(iter, entries)->address) < 0) {
            SLIST_INSERT_AFTER(iter, listener, entries);
            return;
        }
    }
}

void
remove_listener(struct Listener_head *listeners, struct Listener *listener, struct ev_loop *loop) {
    close_listener(loop, listener);
    SLIST_REMOVE(listeners, listener, Listener, entries);
    listener_ref_put(listener);
}

int
valid_listener(const struct Listener *listener) {
    if (listener->accept_cb == NULL) {
        err("No accept callback not specified");
        return 0;
    }

    if (listener->address == NULL) {
        err("No address specified");
        return 0;
    }

    if (!address_is_sockaddr(listener->address)) {
        err("Address not specified as IP/socket");
        return 0;
    }

    switch (address_sa(listener->address)->sa_family) {
        case AF_UNIX:
            break;
        case AF_INET:
            /* fall through */
        case AF_INET6:
            if (address_port(listener->address) == 0) {
                err("No port specified");
                return 0;
            }
            break;
        default:
            err("Invalid address family");
            return 0;
    }

    if (listener->protocol != tls_protocol && listener->protocol != http_protocol) {
        err("Invalid protocol");
        return 0;
    }

    return 1;
}

static int
init_listener(struct Listener *listener, const struct Table_head *tables,
        struct ev_loop *loop) {
    char address[ADDRESS_BUFFER_SIZE];
    struct Table *table = table_lookup(tables, listener->table_name);
    if (table == NULL) {
        err("Table \"%s\" not defined", listener->table_name);
        return -1;
    }
    init_table(table);
    listener->table = table_ref_get(table);

    /* If no port was specified on the fallback address, inherit the address
     * from the listening address */
    if (listener->fallback_address &&
            address_port(listener->fallback_address) == 0)
        address_set_port(listener->fallback_address,
                address_port(listener->address));

    int socket_type = SOCK_STREAM;
#ifdef HAVE_ACCEPT4
    socket_type |= SOCK_NONBLOCK;
#endif
#ifdef SOCK_CLOEXEC
    socket_type |= SOCK_CLOEXEC;
#endif
    int sockfd = socket(address_sa(listener->address)->sa_family, socket_type, 0);
    if (sockfd < 0) {
        err("socket failed: %s", strerror(errno));
        return sockfd;
    }

    if (set_cloexec(sockfd) < 0) {
        err("failed to set close-on-exec on listener socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    /* set SO_REUSEADDR on server socket to facilitate restart */
    int on = 1;
    int result = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (result < 0) {
        err("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        close(sockfd);
        return result;
    }

    /* set SO_KEEPALIVE on the server socket so that abandoned client connections
     * do not linger behind forever */
    result = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    if (result < 0) {
        err("setsockopt SO_KEEPALIVE failed: %s", strerror(errno));
        close(sockfd);
        return result;
    }

    if (listener->reuseport == 1) {
#ifdef SO_REUSEPORT
        /* set SO_REUSEPORT on server socket to allow binding of multiple
         * processes on the same ip:port */
        result = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#else
        result = -ENOSYS;
#endif
        if (result < 0) {
            err("setsockopt SO_REUSEPORT failed: %s", strerror(errno));
            close(sockfd);
            return result;
        }
    }

    if (listener->ipv6_v6only == 1 &&
            address_sa(listener->address)->sa_family == AF_INET6) {
#ifdef IPV6_V6ONLY
        /* set IPV6_V6ONLY on server socket to only accept IPv6 connections on
         * IPv6 listeners */
        result = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#else
        result = -ENOSYS;
#endif
        if (result < 0) {
            err("setsockopt IPV6_V6ONLY failed: %s", strerror(errno));
            close(sockfd);
            return result;
        }
    }

    result = bind(sockfd, address_sa(listener->address),
            address_sa_len(listener->address));
    if (result < 0 && errno == EACCES) {
        /* Retry using binder module */
        close(sockfd);
        sockfd = bind_socket(address_sa(listener->address),
                address_sa_len(listener->address));
        if (sockfd < 0) {
            err("binder failed to bind to %s",
                display_address(listener->address, address, sizeof(address)));
            return sockfd;
        }

        if (set_cloexec(sockfd) < 0) {
            err("failed to set close-on-exec on bound listener socket: %s", strerror(errno));
            close(sockfd);
            return -1;
        }
    } else if (result < 0) {
        err("bind %s failed: %s",
            display_address(listener->address, address, sizeof(address)),
            strerror(errno));
        close(sockfd);
        return result;
    }

    result = listen(sockfd, SOMAXCONN);
    if (result < 0) {
        err("listen failed: %s", strerror(errno));
        close(sockfd);
        return result;
    }

#ifndef HAVE_ACCEPT4
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    ev_io_init(&listener->watcher, accept_cb, sockfd, EV_READ);
    listener->watcher.data = listener;
    listener->backoff_timer.data = listener;

    ev_io_start(loop, &listener->watcher);

    return sockfd;
}

/*
 * Allocate a new server address trying:
 *      1. lookup name in table for hostname or socket address
 *      2. lookup name in table for a wildcard address, then create a new
 *         address based on the request hostname (if valid)
 *      3. use the fallback address
 */
struct LookupResult
listener_lookup_server_address(const struct Listener *listener,
        const char *name, size_t name_len) {
    if (listener == NULL)
        return (struct LookupResult){ .address = NULL };

    if (name == NULL || name_len == 0) {
        return (struct LookupResult){
            .address = listener->fallback_address,
            .use_proxy_header = listener->fallback_use_proxy_header,
        };
    }

    if (listener->table == NULL) {
        return (struct LookupResult){
            .address = listener->fallback_address,
            .use_proxy_header = listener->fallback_use_proxy_header,
        };
    }

    struct LookupResult table_result =
        table_lookup_server_address(listener->table, name, name_len);

    if (table_result.address == NULL) {
        /* No match in table, use fallback address if present */
        return (struct LookupResult){
            .address = listener->fallback_address,
            .use_proxy_header = listener->fallback_use_proxy_header
        };
    } else if (address_is_wildcard(table_result.address)) {
        /* Wildcard table entry, create a new address from hostname */
        struct Address *new_addr = new_address(name);
        if (new_addr == NULL) {
            warn("Invalid hostname %.*s in client request",
                    (int)name_len, name);

            return (struct LookupResult){
                .address = listener->fallback_address,
                .use_proxy_header = listener->fallback_use_proxy_header
            };
        } else if (address_is_sockaddr(new_addr)) {
            warn("Refusing to proxy to socket address literal %.*s in request",
                    (int)name_len, name);
            free(new_addr);

            return (struct LookupResult){
                .address = listener->fallback_address,
                .use_proxy_header = listener->fallback_use_proxy_header
            };
        }

        /* We created a valid new_addr, use the port from wildcard address if
         * present otherwise the listener */
        address_set_port(new_addr, address_port(table_result.address) != 0 ?
                                   address_port(table_result.address) :
                                   address_port(listener->address));


        return (struct LookupResult){
            .address = new_addr,
            .caller_free_address = 1,
            .use_proxy_header = table_result.use_proxy_header
        };
    } else if (address_port(table_result.address) == 0) {
        /* If the server port isn't specified return a new address using the
         * port from the listen, this allows sharing table across listeners */
        struct Address *new_addr = copy_address(table_result.address);

        if (new_addr == NULL) {
            err("Failed to copy backend address for %.*s: %s",
                    (int)name_len,
                    name,
                    strerror(errno));

            return (struct LookupResult){
                .address = listener->fallback_address,
                .use_proxy_header = listener->fallback_use_proxy_header
            };
        }

        address_set_port(new_addr, address_port(listener->address));

        return (struct LookupResult){
            .address = new_addr,
            .caller_free_address = 1,
            .use_proxy_header = table_result.use_proxy_header
        };
    } else {
        return table_result;
    }
}

int
listener_acl_allows(const struct Listener *listener,
        const struct sockaddr_storage *addr) {
    if (listener == NULL)
        return 0;

    if (listener->acl_mode == LISTENER_ACL_MODE_DISABLED)
        return 1;

    int matched = listener_acl_contains(listener, addr);

    if (listener->acl_mode == LISTENER_ACL_MODE_ALLOW_EXCEPT)
        return matched ? 0 : 1;

    if (listener->acl_mode == LISTENER_ACL_MODE_DENY_EXCEPT)
        return matched ? 1 : 0;

    return 1;
}

void
print_listener_config(FILE *file, const struct Listener *listener) {
    assert(listener != NULL);

    char address[ADDRESS_BUFFER_SIZE];
    const struct ListenerACLRule *rule;

    fprintf(file, "listener %s {\n",
            display_address(listener->address, address, sizeof(address)));

    fprintf(file, "\tprotocol %s\n", listener->protocol->name);

    if (listener->table_name)
        fprintf(file, "\ttable %s\n", listener->table_name);

    if (listener->fallback_address &&
            !listener->fallback_use_proxy_header)
        fprintf(file, "\tfallback %s\n",
                display_address(listener->fallback_address,
                    address, sizeof(address)));

    if (listener->fallback_address &&
            listener->fallback_use_proxy_header)
        fprintf(file, "\tfallback %s proxy\n",
                display_address(listener->fallback_address,
                    address, sizeof(address)));

    if (listener->source_address)
        fprintf(file, "\tsource %s\n",
                display_address(listener->source_address,
                    address, sizeof(address)));

    if (listener->reuseport)
        fprintf(file, "\treuseport on\n");

    if (listener->acl_mode != LISTENER_ACL_MODE_DISABLED) {
        const char *policy = listener->acl_mode == LISTENER_ACL_MODE_ALLOW_EXCEPT ?
                "allow_except" : "deny_except";
        fprintf(file, "\tacl %s {\n", policy);
        SLIST_FOREACH(rule, &listener->acl_rules, entries) {
            char cidr_buf[INET6_ADDRSTRLEN + 8];
            const char *cidr = listener_acl_rule_to_string(rule, cidr_buf, sizeof(cidr_buf));
            if (cidr != NULL)
                fprintf(file, "\t\t%s\n", cidr);
        }
        fprintf(file, "\t}\n");
    }

    fprintf(file, "}\n\n");
}

static void
close_listener(struct ev_loop *loop, struct Listener *listener) {
    ev_timer_stop(loop, &listener->backoff_timer);

    if (listener->watcher.fd >= 0) {
        ev_io_stop(loop, &listener->watcher);
        close(listener->watcher.fd);
        listener->watcher.fd = -1;
    }
}

static void
free_listener(struct Listener *listener) {
    if (listener == NULL)
        return;

    listener_acl_clear(listener);

    free(listener->address);
    free(listener->fallback_address);
    free(listener->source_address);
    free(listener->table_name);

    table_ref_put(listener->table);
    listener->table = NULL;

    logger_ref_put(listener->access_log);
    listener->access_log = NULL;

    free(listener);
}

void
free_listeners(struct Listener_head *listeners, struct ev_loop *loop) {
    struct Listener *iter;

    while ((iter = SLIST_FIRST(listeners)) != NULL)
        remove_listener(listeners, iter, loop);
}

/*
 * Listener reference counting
 *
 * Since when reloading the configuration a listener with active connections
 * could be removed and connections require a reference to to the listener on
 * which they where received we need to allow listeners to linger outside the
 * listeners list in the active configuration, and free them when their last
 * connection closes.
 *
 * Accomplishing this with reference counting: membership in a Config listener
 * list counts as one as does each connection.
 */
void
listener_ref_put(struct Listener *listener) {
    if (listener == NULL)
        return;

    assert(listener->reference_count > 0);
    listener->reference_count--;
    if (listener->reference_count == 0)
        free_listener(listener);
}

struct Listener *
listener_ref_get(struct Listener *listener) {
    assert(listener != NULL);

    listener->reference_count++;
    return listener;
}

static void
accept_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct Listener *listener = (struct Listener *)w->data;

    if (!(revents & EV_READ))
        return;

    int last_errno = 0;

    for (int i = 0; i < LISTENER_ACCEPT_MAX_BATCH; i++) {
        int result = listener->accept_cb(listener, loop);
        if (result > 0) {
            last_errno = 0;
            continue;
        }

        last_errno = errno;

        if (last_errno == EINTR)
            continue;

        if (last_errno == EAGAIN || last_errno == EWOULDBLOCK ||
                last_errno == 0)
            break;

        break;
    }

    if (last_errno == EMFILE || last_errno == ENFILE) {
        char address_buf[ADDRESS_BUFFER_SIZE];
        int backoff_time = 2;

        err("File descriptor limit reached! "
            "Suspending accepting new connections on %s for %d seconds",
            display_address(listener->address, address_buf, sizeof(address_buf)),
            backoff_time);
        ev_io_stop(loop, w);

        ev_timer_set(&listener->backoff_timer, backoff_time, 0.0);
        ev_timer_start(loop, &listener->backoff_timer);
    }
}

static void
backoff_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct Listener *listener = (struct Listener *)w->data;

    if (revents & EV_TIMER) {
        ev_timer_stop(loop, &listener->backoff_timer);

        ev_io_set(&listener->watcher, listener->watcher.fd, EV_READ);
        ev_io_start(loop, &listener->watcher);
    }
}
