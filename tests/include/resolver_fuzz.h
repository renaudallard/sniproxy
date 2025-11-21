/*
 * Helper interfaces exposed only to fuzzing builds so resolver internals
 * can be exercised without duplicating private structures.
 */
#ifndef RESOLVER_FUZZ_H
#define RESOLVER_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <ares_dns.h>

struct ResolverChildQuery;

struct ResolverChildQuery *resolver_fuzz_query_create(void);
void resolver_fuzz_query_configure(struct ResolverChildQuery *query,
        int cancelled, int pending_v4, int pending_v6, int callback_completed);
void resolver_fuzz_query_reset(struct ResolverChildQuery *query);
void resolver_fuzz_query_free(struct ResolverChildQuery *query);
size_t resolver_fuzz_query_response_count(const struct ResolverChildQuery *query);
void resolver_fuzz_handle_addrinfo(struct ResolverChildQuery *query,
        int status, struct ares_addrinfo *result, int family);
void resolver_fuzz_query_set_id(struct ResolverChildQuery *query, uint32_t id);

#endif /* RESOLVER_FUZZ_H */
