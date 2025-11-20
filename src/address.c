/*
 * Copyright (c) 2013, Dustin Lundquist <dustin@null-ptr.net>
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* tolower */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_pton */
#include <sys/un.h>
#include "address.h"


struct Address {
    enum {
        HOSTNAME,
        SOCKADDR,
        WILDCARD,
    } type;

    size_t len;     /* length of data */
    uint16_t port;  /* for hostname and wildcard */
    union {
        long double ld;
        void *ptr;
        uintmax_t um;
    } align;        /* ensure data[] is suitably aligned */
    char data[];
};


static const char valid_label_bytes[] =
"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";


#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))


static int valid_hostname(const char *);

static struct Address *
apply_port_if_needed(struct Address *addr, int has_port, uint16_t port) {
    if (addr != NULL && has_port)
        address_set_port(addr, port);

    return addr;
}


struct Address *
new_address(const char *hostname_or_ip) {
    if (hostname_or_ip == NULL)
        return NULL;

    union {
        struct sockaddr a;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_storage s;
    } s;
    char ip_buf[ADDRESS_BUFFER_SIZE];
    const char *input = hostname_or_ip;
    uint16_t parsed_port = 0;
    int has_port = 0;

    for (;;) {
        char *port;
        size_t len;

        /* IPv6 address */
        /* we need to test for raw IPv6 address for IPv4 port combinations since a
         * colon would give false positives
         */
        memset(&s, 0, sizeof(s));
        if (inet_pton(AF_INET6, input, &s.in6.sin6_addr) == 1) {
            s.in6.sin6_family = AF_INET6;
            return apply_port_if_needed(new_address_sa(&s.a, sizeof(s.in6)),
                    has_port, parsed_port);
        }

        /* Unix socket */
        memset(&s, 0, sizeof(s));
        if (strncmp("unix:", input, 5) == 0) {
            if (strlen(input) >= sizeof(s.un.sun_path))
                return NULL;

            /* XXX: only supporting pathname unix sockets */
            s.un.sun_family = AF_UNIX;
            strncpy(s.un.sun_path,
                    input + 5,
                    sizeof(s.un.sun_path) - 1);
            s.un.sun_path[sizeof(s.un.sun_path) - 1] = '\0';

            return apply_port_if_needed(new_address_sa(&s.a,
                        offsetof(struct sockaddr_un, sun_path) +
                        strlen(s.un.sun_path) + 1),
                    has_port, parsed_port);
        }

        /* Trailing port */
        if ((port = strrchr(input, ':')) != NULL &&
                is_numeric(port + 1)) {
            len = (size_t)(port - input);
            errno = 0;
            unsigned long port_num = strtoul(port + 1, NULL, 10);

            if (len < sizeof(ip_buf) && errno == 0 && port_num <= UINT16_MAX) {
                strncpy(ip_buf, input, len);
                ip_buf[len] = '\0';
                input = ip_buf;
                parsed_port = (uint16_t)port_num;
                has_port = 1;
                continue;
            }
        }

        /* Wildcard */
        if (strcmp("*", input) == 0) {
            struct Address *addr = malloc(sizeof(struct Address));
            if (addr != NULL) {
                addr->type = WILDCARD;
                addr->len = 0;
                address_set_port(addr, 0);
            }
            return apply_port_if_needed(addr, has_port, parsed_port);
        }

        /* IPv4 address */
        memset(&s, 0, sizeof(s));
        if (inet_pton(AF_INET, input, &s.in.sin_addr) == 1) {
            s.in.sin_family = AF_INET;
            return apply_port_if_needed(new_address_sa(&s.a, sizeof(s.in)),
                    has_port, parsed_port);
        }

        /* [IPv6 address] */
        memset(&s, 0, sizeof(s));
        if (input[0] == '[' &&
                (port = strchr(input, ']')) != NULL) {
            len = (size_t)(port - input - 1);
            if (len >= sizeof(ip_buf))
                return NULL;

            /* inet_pton() will not parse the IP correctly unless it is in a
             * separate string. Use memmove() instead of memcpy() because
             * input may already point inside ip_buf when we've previously
             * stripped a trailing port.
             */
            memmove(ip_buf, input + 1, len);
            ip_buf[len] = '\0';

            if (inet_pton(AF_INET6, ip_buf,
                          &s.in6.sin6_addr) == 1) {
                s.in6.sin6_family = AF_INET6;

                return apply_port_if_needed(new_address_sa(&s.a, sizeof(s.in6)),
                        has_port, parsed_port);
            }
        }

        /* hostname */
        if (valid_hostname(input)) {
            len = strlen(input);
            struct Address *addr = malloc(
                    offsetof(struct Address, data) + len + 1);
            if (addr != NULL) {
                addr->type = HOSTNAME;
                addr->port = 0;
                addr->len = len;
                memcpy(addr->data, input, len);
                addr->data[addr->len] = '\0';

                /* Store address in lower case */
                for (char *c = addr->data; *c != '\0'; c++)
                    *c = (char)tolower((unsigned char)*c);
            }

            return apply_port_if_needed(addr, has_port, parsed_port);
        }

        return NULL;
    }
}

struct Address *
new_address_sa(const struct sockaddr *sa, socklen_t sa_len) {
    if (sa == NULL || sa_len == 0 ||
            sa_len > sizeof(struct sockaddr_storage))
        return NULL;

    struct Address *addr = malloc(offsetof(struct Address, data) + sa_len);
    if (addr != NULL) {
        addr->type = SOCKADDR;
        addr->len = sa_len;
        memcpy(addr->data, sa, sa_len);
        addr->port = address_port(addr);
    }

    return addr;
}

struct Address *
copy_address(const struct Address *addr) {
    size_t len = address_len(addr);
    struct Address *new_addr = malloc(len);

    if (new_addr != NULL)
        memcpy(new_addr, addr, len);

    return new_addr;
}

size_t
address_len(const struct Address *addr) {
    if (addr == NULL)
        return 0;

    switch (addr->type) {
        case HOSTNAME:
            /* include trailing null byte */
            return offsetof(struct Address, data) + addr->len + 1;
        case SOCKADDR:
            return offsetof(struct Address, data) + addr->len;
        case WILDCARD:
            return sizeof(struct Address);
        default:
            return 0;
    }
}

int
address_compare(const struct Address *addr_1, const struct Address *addr_2) {
    if (addr_1 == NULL && addr_2 == NULL)
        return 0;
    if (addr_1 == NULL)
        return -1;
    if (addr_2 == NULL)
        return 1;

    if (addr_1->type < addr_2->type)
        return -1;
    if (addr_1->type > addr_2->type)
        return 1;

    size_t addr1_len = addr_1->len;
    size_t addr2_len = addr_2->len;
    int result = memcmp(addr_1->data, addr_2->data, MIN(addr1_len, addr2_len));

    if (result == 0) { /* they match, find a tie breaker */
        if (addr1_len < addr2_len)
            return -1;
        if (addr1_len > addr2_len)
            return 1;

        if (addr_1->port < addr_2->port)
            return -1;
        if (addr_1->port > addr_2->port)
            return 1;
    }

    return result;
}

int
address_is_hostname(const struct Address *addr) {
    return addr != NULL && addr->type == HOSTNAME;
}

int
address_is_sockaddr(const struct Address *addr) {
    return addr != NULL && addr->type == SOCKADDR;
}

int
address_is_wildcard(const struct Address *addr) {
    return addr != NULL && addr->type == WILDCARD;
}

const char *
address_hostname(const struct Address *addr) {
    if (addr == NULL)
        return NULL;

    if (addr->type != HOSTNAME)
        return NULL;

    return addr->data;
}

const struct sockaddr *
address_sa(const struct Address *addr) {
    if (addr == NULL)
        return NULL;

    if (addr->type != SOCKADDR)
        return NULL;

    return (struct sockaddr *)addr->data;
}

socklen_t
address_sa_len(const struct Address *addr) {
    if (addr == NULL)
        return 0;

    if (addr->type != SOCKADDR)
        return 0;

    return addr->len;
}

uint16_t
address_port(const struct Address *addr) {
    if (addr == NULL)
        return 0;

    switch (addr->type) {
        case HOSTNAME:
            return addr->port;
        case SOCKADDR: {
            const struct sockaddr *sa = address_sa(addr);
            socklen_t sa_len = address_sa_len(addr);

            if (sa == NULL)
                return 0;

            switch (sa->sa_family) {
                case AF_INET:
                    if (sa_len < sizeof(struct sockaddr_in))
                        return 0;
                    return ntohs(((struct sockaddr_in *)addr->data)
                            ->sin_port);
                case AF_INET6:
                    if (sa_len < sizeof(struct sockaddr_in6))
                        return 0;
                    return ntohs(((struct sockaddr_in6 *)addr->data)
                            ->sin6_port);
                case AF_UNIX:
                case AF_UNSPEC:
                    return 0;
                default:
                    return 0;
            }
        }
        case WILDCARD:
            return addr->port;
        default:
            /* invalid Address type */
            return 0;
    }
}

void
address_set_port(struct Address *addr, uint16_t port) {
    if (addr == NULL)
        return;

    switch (addr->type) {
        case SOCKADDR: {
            struct sockaddr *sa = (struct sockaddr *)address_sa(addr);
            socklen_t sa_len = address_sa_len(addr);

            if (sa == NULL)
                break;

            switch (sa->sa_family) {
                case AF_INET:
                    if (sa_len < sizeof(struct sockaddr_in))
                        break;
                    (((struct sockaddr_in *)sa) ->sin_port) =
                        htons(port);
                    break;
                case AF_INET6:
                    if (sa_len < sizeof(struct sockaddr_in6))
                        break;
                    (((struct sockaddr_in6 *)sa) ->sin6_port) =
                        htons(port);
                    break;
                case AF_UNIX:
                case AF_UNSPEC:
                    /* no op */
                    break;
                default:
                    break;
            }
        }
            /* fall through */
        case HOSTNAME:
        case WILDCARD:
            addr->port = port;
            break;
        default:
            /* invalid Address type */
            break;
    }
}

int
address_set_port_str(struct Address *addr, const char* str) {
    char *endptr;
    unsigned long port;

    if (str == NULL || *str == '\0')
        return 0;

    errno = 0;
    port = strtoul(str, &endptr, 10);

    if (errno != 0 || *endptr != '\0' || port > UINT16_MAX)
        return 0;

    address_set_port(addr, (uint16_t)port);
    return 1;
}

const char *
display_address(const struct Address *addr, char *buffer, size_t buffer_len) {
    if (buffer == NULL || buffer_len == 0)
        return "(invalid)";

    if (addr == NULL) {
        snprintf(buffer, buffer_len, "(null)");
        return buffer;
    }

    switch (addr->type) {
        case HOSTNAME:
            if (addr->port != 0)
                snprintf(buffer, buffer_len, "%s:%" PRIu16,
                        addr->data,
                        addr->port);
            else
                snprintf(buffer, buffer_len, "%s",
                        addr->data);
            return buffer;
        case SOCKADDR:
            return display_sockaddr(addr->data,
                    (socklen_t)addr->len,
                    buffer, buffer_len);
        case WILDCARD:
            if (addr->port != 0)
                snprintf(buffer, buffer_len, "*:%" PRIu16,
                        addr->port);
            else
                snprintf(buffer, buffer_len, "*");
            return buffer;
        default:
            snprintf(buffer, buffer_len, "(invalid)");
            return buffer;
    }
}

const char *
display_sockaddr(const void *sa_ptr, socklen_t sa_len, char *buffer, size_t buffer_len) {
    const struct sockaddr *sa = (const struct sockaddr *)sa_ptr;
    char ip[INET6_ADDRSTRLEN];

    if (buffer == NULL || buffer_len == 0)
        return "(invalid)";

    buffer[0] = '\0';

    if (sa == NULL || sa_len < (socklen_t)sizeof(sa->sa_family)) {
        snprintf(buffer, buffer_len, "(null)");
        return buffer;
    }

    switch (sa->sa_family) {
        case AF_INET:
            if (sa_len < (socklen_t)sizeof(struct sockaddr_in))
                break;

            inet_ntop(AF_INET,
                      &((const struct sockaddr_in *)sa)->sin_addr,
                      ip, sizeof(ip));

            if (((const struct sockaddr_in *)sa)->sin_port != 0)
                snprintf(buffer, buffer_len, "%s:%" PRIu16, ip,
                        ntohs(((const struct sockaddr_in *)sa)->sin_port));
            else
                snprintf(buffer, buffer_len, "%s", ip);

            break;
        case AF_INET6:
            if (sa_len < (socklen_t)sizeof(struct sockaddr_in6))
                break;

            inet_ntop(AF_INET6,
                      &((const struct sockaddr_in6 *)sa)->sin6_addr,
                      ip, sizeof(ip));

            if (((const struct sockaddr_in6 *)sa)->sin6_port != 0)
                snprintf(buffer, buffer_len, "[%s]:%" PRIu16, ip,
                         ntohs(((const struct sockaddr_in6 *)sa)->sin6_port));
            else
                snprintf(buffer, buffer_len, "[%s]", ip);

            break;
        case AF_UNIX: {
            const struct sockaddr_un *sun = (const struct sockaddr_un *)sa;
            size_t offset = offsetof(struct sockaddr_un, sun_path);
            size_t available = 0;

            if (sa_len > (socklen_t)offset)
                available = (size_t)(sa_len - (socklen_t)offset);
            if (available > sizeof(sun->sun_path))
                available = sizeof(sun->sun_path);

            while (available > 0 && sun->sun_path[available - 1] == '\0')
                available--;

            size_t pos = snprintf(buffer, buffer_len, "unix:");
            if (pos >= buffer_len)
                return buffer;

            if (available == 0) {
                buffer[pos] = '\0';
                break;
            }

            const unsigned char *name = (const unsigned char *)sun->sun_path;
            if (sun->sun_path[0] == '\0' && available > 0) {
                if (pos + 1 >= buffer_len) {
                    buffer[buffer_len - 1] = '\0';
                    break;
                }
                buffer[pos++] = '@';
                name++;
                available--;
            }

            for (size_t i = 0; i < available && pos < buffer_len - 1; i++) {
                unsigned char ch = name[i];

                if (isprint(ch) && ch != '\\') {
                    buffer[pos++] = (char)ch;
                } else {
                    if (pos + 4 >= buffer_len) {
                        pos = buffer_len - 1;
                        break;
                    }

                    int written = snprintf(buffer + pos, buffer_len - pos,
                            "\\x%02x", ch);
                    if (written < 0)
                        break;
                    pos += (size_t)written;
                }
            }

            buffer[MIN(pos, buffer_len - 1)] = '\0';
            break;
        }
        case AF_UNSPEC:
            snprintf(buffer, buffer_len, "NONE");
            break;
        default:
            snprintf(buffer, buffer_len, "UNKNOWN");
            break;
    }

    return buffer;
}

int
is_numeric(const char *s) {
    char *endptr;

    if (s == NULL || *s == '\0')
        return 0;

    if (*s == '+' || *s == '-' || isspace((unsigned char)*s))
        return 0;

    errno = 0;
    (void)strtoul(s, &endptr, 10);

    if (errno != 0)
        return 0;

    return *endptr == '\0'; /* entire string was numeric */
}

static int
valid_hostname(const char *hostname) {
    if (hostname == NULL)
        return 0;

    size_t hostname_len = strlen(hostname);
    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *hostname_end = hostname + hostname_len;
    for (const char *label = hostname; label < hostname_end;) {
        size_t label_len = (size_t)(hostname_end - label);
        char *next_dot = strchr(label, '.');
        if (next_dot != NULL)
            label_len = (size_t)(next_dot - label);
        if (label + label_len > hostname_end)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, valid_label_bytes) < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}
