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

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* The SplitMix64 finalizer, a bijection on 64 bit values that spreads
 * every input bit over the whole result. Hash tables key it with an
 * arc4random value, mixed in before it, so that which inputs share a
 * bucket cannot be known without the key. */
static inline uint64_t
hash_mix64(uint64_t v) {
    v += 0x9e3779b97f4a7c15ULL;
    v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ULL;
    v = (v ^ (v >> 27)) * 0x94d049bb133111ebULL;
    return v ^ (v >> 31);
}

static inline uint32_t
hash_mix64_to_32(uint64_t v) {
    v = hash_mix64(v);
    return (uint32_t)(v ^ (v >> 32));
}

/* An IPv4 or IPv6 multicast group, the IPv4-mapped form included. Such
 * a group is never a backend: a TCP connect to one fails, but a DTLS
 * session would send its client's datagrams to every member, so a
 * hostname resolving to one is refused with or without a backend ACL.
 * Nor does the binder bind one: the kernel lets any socket share a
 * group's port, root's included. */
static inline int
sockaddr_is_multicast(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        return IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
    }

    if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

        return IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) ||
                (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) &&
                 (sin6->sin6_addr.s6_addr[12] & 0xf0) == 0xe0);
    }

    return 0;
}

/* 1 for yes, true or on, 0 for no, false or off, in any case, and -1 for
 * anything else. */
static inline int
parse_boolean(const char *value) {
    static const char *const true_words[] = { "yes", "true", "on" };
    static const char *const false_words[] = { "no", "false", "off" };

    for (size_t i = 0; i < sizeof(true_words) / sizeof(true_words[0]); i++) {
        if (strcasecmp(value, true_words[i]) == 0)
            return 1;
        if (strcasecmp(value, false_words[i]) == 0)
            return 0;
    }

    return -1;
}

#if !defined(HAVE_REALLOCARRAY) && !defined(HAVE_BSD_STDLIB_H)
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
static inline void *
sniproxy_reallocarray(void *ptr, size_t nmemb, size_t size)
{
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, nmemb * size);
}
#define reallocarray sniproxy_reallocarray
#endif

#endif
