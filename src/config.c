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
#include <limits.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include "cfg_parser.h"
#include "config.h"
#include "logger.h"
#include "connection.h"


struct LoggerBuilder {
    const char *filename;
    const char *syslog_facility;
    int priority;
};

struct ListenerACLBuilder {
    enum ListenerACLMode mode;
    struct ListenerACLRule_head rules;
};

struct ListenerACLRuleValue {
    char *value;
};

enum GlobalACLPolicy {
    GLOBAL_ACL_POLICY_UNSET = 0,
    GLOBAL_ACL_POLICY_ALLOW,
    GLOBAL_ACL_POLICY_DENY,
};

static enum GlobalACLPolicy global_acl_policy = GLOBAL_ACL_POLICY_UNSET;

static int accept_username(struct Config *, const char *);
static int accept_groupname(struct Config *, const char *);
static int accept_pidfile(struct Config *, const char *);
static int accept_per_ip_connection_rate(struct Config *, const char *);
static int end_listener_stanza(struct Config *, struct Listener *);
static int end_table_stanza(struct Config *, struct Table *);
static int end_backend(struct Table *, struct Backend *);
static struct LoggerBuilder *new_logger_builder(void);
static int accept_logger_filename(struct LoggerBuilder *, const char *);
static int accept_logger_syslog_facility(struct LoggerBuilder *, const char *);
static int accept_logger_priority(struct LoggerBuilder *, const char *);
static int end_error_logger_stanza(struct Config *, struct LoggerBuilder *);
static int end_global_access_logger_stanza(struct Config *, struct LoggerBuilder *);
static int end_listener_access_logger_stanza(struct Listener *, struct LoggerBuilder *);
static struct ResolverConfig *new_resolver_config(void);
static int accept_resolver_nameserver(struct ResolverConfig *, const char *);
static int accept_resolver_search(struct ResolverConfig *, const char *);
static int accept_resolver_mode(struct ResolverConfig *, const char *);
static int accept_resolver_max_queries(struct ResolverConfig *, const char *);
static int accept_resolver_dnssec_validation(struct ResolverConfig *, const char *);
static int end_resolver_stanza(struct Config *, struct ResolverConfig *);
static inline size_t string_vector_len(char **);
static int append_to_string_vector(char ***, const char *) __attribute__((nonnull(1)));
static void free_string_vector(char **);
static void print_resolver_config(FILE *, struct ResolverConfig *);


static void *new_listener_acl_builder(void);
static int accept_listener_acl_policy(struct ListenerACLBuilder *, const char *);
static int accept_listener_acl_cidr(struct ListenerACLBuilder *, const char *);
static int end_listener_acl_stanza(struct Listener *, struct ListenerACLBuilder *);
static struct ListenerACLRule *new_listener_acl_rule_from_cidr(const char *);
static void *new_listener_acl_value(void);
static int accept_listener_acl_value(struct ListenerACLRuleValue *, const char *);
static int end_listener_acl_value(struct ListenerACLBuilder *, struct ListenerACLRuleValue *);
static void free_listener_acl_builder(struct ListenerACLBuilder *);

static const struct Keyword listener_acl_stanza_grammar[];

static const struct Keyword logger_stanza_grammar[] = {
    {
        .keyword="filename",
        .parse_arg=(int(*)(void *, const char *))accept_logger_filename,
    },
    {
        .keyword="syslog",
        .parse_arg=(int(*)(void *, const char *))accept_logger_syslog_facility,
    },
    {
        .keyword="priority",
        .parse_arg=(int(*)(void *, const char *))accept_logger_priority,
    },
    {
        .keyword="acl",
        .create=(void *(*)(void))new_listener_acl_builder,
        .parse_arg=(int(*)(void *, const char *))accept_listener_acl_policy,
        .block_grammar=listener_acl_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_listener_acl_stanza,
    },
    {
        .keyword = NULL,
    },
};

static const struct Keyword resolver_stanza_grammar[] = {
    {
        .keyword="nameserver",
        .parse_arg=(int(*)(void *, const char *))accept_resolver_nameserver,
    },
    {
        .keyword="search",
        .parse_arg=(int(*)(void *, const char *))accept_resolver_search,
    },
    {
        .keyword="mode",
        .parse_arg=(int(*)(void *, const char *))accept_resolver_mode,
    },
    {
        .keyword="max_concurrent_queries",
        .parse_arg=(int(*)(void *, const char *))accept_resolver_max_queries,
    },
    {
        .keyword="dnssec_validation",
        .parse_arg=(int(*)(void *, const char *))accept_resolver_dnssec_validation,
    },
    {
        .keyword = NULL,
    },
};

static const struct Keyword listener_stanza_grammar[] = {
    {
        .keyword="protocol",
        .parse_arg=(int(*)(void *, const char *))accept_listener_protocol,
    },
    {
        .keyword="proto",
        .parse_arg=(int(*)(void *, const char *))accept_listener_protocol,
    },
    {
        .keyword="reuseport",
        .parse_arg=(int(*)(void *, const char *))accept_listener_reuseport,
    },
    {
        .keyword="ipv6_v6only",
        .parse_arg=(int(*)(void *, const char *))accept_listener_ipv6_v6only,
    },
    {
        .keyword="table",
        .parse_arg=(int(*)(void *, const char *))accept_listener_table_name,
    },
    {
        .keyword="fallback",
        .parse_arg=    (int(*)(void *, const char *))accept_listener_fallback_address,
    },
    {
        .keyword="source",
        .parse_arg=(int(*)(void *, const char *))accept_listener_source_address,
    },
    {
        .keyword="access_log",
        .create=(void *(*)(void))new_logger_builder,
        .parse_arg=(int(*)(void *, const char *))accept_logger_filename,
        .block_grammar=logger_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_listener_access_logger_stanza,
    },
    {
        .keyword="bad_requests",
        .parse_arg= (int(*)(void *, const char *))accept_listener_bad_request_action,
    },
    {
        .keyword = NULL,
    },
};

static const struct Keyword listener_acl_stanza_grammar[] = {
    {
        .keyword="cidr",
        .parse_arg=(int(*)(void *, const char *))accept_listener_acl_cidr,
    },
    {
        .create=(void *(*)(void))new_listener_acl_value,
        .parse_arg=(int(*)(void *, const char *))accept_listener_acl_value,
        .finalize=(int(*)(void *, void *))end_listener_acl_value,
    },
    {
        .keyword = NULL,
    },
};

static struct Keyword table_stanza_grammar[] = {
    {
        .create=(void *(*)(void))new_backend,
        .parse_arg=(int(*)(void *, const char *))accept_backend_arg,
        .finalize=(int(*)(void *, void *))end_backend,
    },
    {
        .keyword = NULL,
    },
};

static struct Keyword global_grammar[] = {
    {
        .keyword="username",
        .parse_arg=(int(*)(void *, const char *))accept_username,
    },
    {
        .keyword="user",
        .parse_arg=(int(*)(void *, const char *))accept_username,
    },
    {
        .keyword="groupname",
        .parse_arg=    (int(*)(void *, const char *))accept_groupname,
    },
    {
        .keyword="group",
        .parse_arg=    (int(*)(void *, const char *))accept_groupname,
    },
    {
        .keyword="pidfile",
        .parse_arg=(int(*)(void *, const char *))accept_pidfile,
    },
    {
        .keyword="per_ip_connection_rate",
        .parse_arg=(int(*)(void *, const char *))accept_per_ip_connection_rate,
    },
    {
        .keyword="resolver",
        .create=(void *(*)(void))new_resolver_config,
        .block_grammar=resolver_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_resolver_stanza,
    },
    {
        .keyword="error_log",
        .create=(void *(*)(void))new_logger_builder,
        .block_grammar=logger_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_error_logger_stanza,
    },
    {
        .keyword="access_log",
        .create=(void *(*)(void))new_logger_builder,
        .block_grammar=logger_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_global_access_logger_stanza,
    },
    {
        .keyword="listener",
        .create=(void *(*)(void))new_listener,
        .parse_arg=(int(*)(void *, const char *))accept_listener_arg,
        .block_grammar=listener_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_listener_stanza,
    },
    {
        .keyword="listen",
        .create=(void *(*)(void))new_listener,
        .parse_arg=(int(*)(void *, const char *))accept_listener_arg,
        .block_grammar=listener_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_listener_stanza,
    },
    {
        .keyword="table",
        .create=(void *(*)(void))new_table,
        .parse_arg=(int(*)(void *, const char *))accept_table_arg,
        .block_grammar=table_stanza_grammar,
        .finalize=(int(*)(void *, void *))end_table_stanza,
    },
    {
        .keyword = NULL,
    },
};

static const char *const resolver_mode_names[] = {
    "DEFAULT",
    "ipv4_only",
    "ipv6_only",
    "ipv4_first",
    "ipv6_first",
};

static const char *const dnssec_validation_mode_names[] = {
    "off",
    "relaxed",
    "strict",
};


struct Config *
init_config(const char *filename, struct ev_loop *loop) {
    struct Config *config = calloc(1, sizeof(struct Config));
    if (config == NULL) {
        err("%s: malloc", __func__);
        return NULL;
    }

    config->resolver.max_concurrent_queries = DEFAULT_DNS_QUERY_CONCURRENCY;

    SLIST_INIT(&config->listeners);
    SLIST_INIT(&config->tables);

    config->filename = strdup(filename);
    if (config->filename == NULL) {
        err("%s: strdup", __func__);
        free_config(config, loop);
        return NULL;
    }

    global_acl_policy = GLOBAL_ACL_POLICY_UNSET;

    FILE *file = fopen(config->filename, "r");
    if (file == NULL) {
        err("%s: unable to open configuration file: %s", __func__, config->filename);
        free_config(config, loop);
        return NULL;
    }

    if (parse_config(config, file, global_grammar, "global") <= 0) {
        off_t whence = ftello(file);
        char line[256];

        err("error parsing %s at %jd near:", filename, (intmax_t)whence);
        fseeko(file, (off_t)-20, SEEK_CUR);
        for (int i = 0; i < 5; i++)
            err(" %jd\t%s", (intmax_t)ftello(file), fgets(line, sizeof(line), file));

        free_config(config, loop);
        config = NULL;
    }

    fclose(file);

    /* Listeners without access logger defined used global access log */
    if (config != NULL && config->access_log != NULL) {
        struct Listener *listener = SLIST_FIRST(&config->listeners);
        while (listener != NULL) {
            if (listener->access_log == NULL) {
                listener->access_log = logger_ref_get(config->access_log);
            }
            listener = SLIST_NEXT(listener, entries);
        }
    }

    return(config);
}

void
free_config(struct Config *config, struct ev_loop *loop) {
    free(config->filename);
    free(config->user);
    free(config->group);
    free(config->pidfile);

    free_string_vector(config->resolver.nameservers);
    config->resolver.nameservers = NULL;
    free_string_vector(config->resolver.search);
    config->resolver.search = NULL;

    logger_ref_put(config->access_log);
    free_listeners(&config->listeners, loop);
    free_tables(&config->tables);

    free(config);
}

void
reload_config(struct Config *config, struct ev_loop *loop) {
    notice("reloading configuration from %s", config->filename);

    struct Config *new_config = init_config(config->filename, loop);
    if (new_config == NULL) {
        err("failed to reload %s", config->filename);
        return;
    }

    /* update access_log */
    logger_ref_put(config->access_log);
    config->access_log = logger_ref_get(new_config->access_log);

    reload_tables(&config->tables, &new_config->tables);

    listeners_reload(&config->listeners, &new_config->listeners,
            &config->tables, loop);

    config->per_ip_connection_rate = new_config->per_ip_connection_rate;
    connections_set_per_ip_connection_rate(config->per_ip_connection_rate);

    config->resolver.max_concurrent_queries = new_config->resolver.max_concurrent_queries;
    connections_set_dns_query_limit(config->resolver.max_concurrent_queries);

    free_config(new_config, loop);
}

void
print_config(FILE *file, struct Config *config) {
    struct Listener *listener = NULL;
    struct Table *table = NULL;

    if (config->filename)
        fprintf(file, "# Config loaded from %s\n\n", config->filename);

    if (config->user)
        fprintf(file, "username %s\n\n", config->user);

    if (config->pidfile)
        fprintf(file, "pidfile %s\n\n", config->pidfile);

    if (config->per_ip_connection_rate > 0.0)
        fprintf(file, "per_ip_connection_rate %.3f\n\n", config->per_ip_connection_rate);

    print_resolver_config(file, &config->resolver);

    SLIST_FOREACH(listener, &config->listeners, entries) {
        print_listener_config(file, listener);
    }

    SLIST_FOREACH(table, &config->tables, entries) {
        print_table_config(file, table);
    }
}

static void *
new_listener_acl_builder(void) {
    struct ListenerACLBuilder *builder = calloc(1, sizeof(*builder));
    if (builder == NULL) {
        err("%s: calloc", __func__);
        return NULL;
    }

    builder->mode = LISTENER_ACL_MODE_ALLOW_EXCEPT;
    SLIST_INIT(&builder->rules);

    return builder;
}

static void
free_listener_acl_builder(struct ListenerACLBuilder *builder) {
    struct ListenerACLRule *rule;

    if (builder == NULL)
        return;

    while ((rule = SLIST_FIRST(&builder->rules)) != NULL) {
        SLIST_REMOVE_HEAD(&builder->rules, entries);
        free(rule);
    }

    free(builder);
}

static struct ListenerACLRule *
new_listener_acl_rule_from_cidr(const char *value) {
    struct ListenerACLRule *rule = NULL;
    char *tmp = NULL;
    char *slash = NULL;
    char *prefix = NULL;
    char *endptr = NULL;
    long prefix_len;

    if (value == NULL)
        return NULL;

    tmp = strdup(value);
    if (tmp == NULL) {
        err("%s: strdup", __func__);
        return NULL;
    }

    slash = strchr(tmp, '/');
    if (slash == NULL) {
        err("ACL entry must be specified as CIDR: %s", value);
        free(tmp);
        return NULL;
    }

    *slash = '\0';
    prefix = slash + 1;
    errno = 0;
    prefix_len = strtol(prefix, &endptr, 10);
    if (errno != 0 || endptr == prefix || *endptr != '\0' || prefix_len < 0) {
        err("Invalid prefix length in ACL entry: %s", value);
        free(tmp);
        return NULL;
    }

    rule = calloc(1, sizeof(*rule));
    if (rule == NULL) {
        err("%s: calloc", __func__);
        free(tmp);
        return NULL;
    }

    if (inet_pton(AF_INET, tmp, &rule->network.in) == 1) {
        if (prefix_len > 32) {
            err("IPv4 prefix length out of range in ACL entry: %s", value);
            free(rule);
            free(tmp);
            return NULL;
        }
        rule->family = AF_INET;
    } else if (inet_pton(AF_INET6, tmp, &rule->network.in6) == 1) {
        if (prefix_len > 128) {
            err("IPv6 prefix length out of range in ACL entry: %s", value);
            free(rule);
            free(tmp);
            return NULL;
        }
        rule->family = AF_INET6;
    } else {
        err("Invalid network address in ACL entry: %s", value);
        free(rule);
        free(tmp);
        return NULL;
    }

    rule->prefix_len = (uint8_t)prefix_len;

    free(tmp);

    return rule;
}

static void *
new_listener_acl_value(void) {
    struct ListenerACLRuleValue *value = calloc(1, sizeof(*value));
    if (value == NULL) {
        err("%s: calloc", __func__);
        return NULL;
    }

    return value;
}

static int
accept_listener_acl_value(struct ListenerACLRuleValue *entry, const char *value) {
    if (entry == NULL || value == NULL)
        return 0;

    if (entry->value != NULL) {
        err("Unexpected extra token in ACL entry: %s", value);
        return 0;
    }

    entry->value = strdup(value);
    if (entry->value == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
end_listener_acl_value(struct ListenerACLBuilder *builder, struct ListenerACLRuleValue *entry) {
    int result = 0;

    if (builder == NULL || entry == NULL) {
        free(entry);
        return 0;
    }

    if (entry->value == NULL) {
        err("ACL entry must specify an address or network");
        free(entry);
        return 0;
    }

    result = accept_listener_acl_cidr(builder, entry->value);

    free(entry->value);
    free(entry);

    return result;
}

static int
accept_listener_acl_policy(struct ListenerACLBuilder *builder, const char *policy) {
    if (builder == NULL || policy == NULL)
        return 0;

    if (strcasecmp(policy, "allow_except") == 0) {
        if (global_acl_policy == GLOBAL_ACL_POLICY_DENY) {
            err("acl allow_except and deny_except stanzas are mutually exclusive");
            return 0;
        }
        global_acl_policy = GLOBAL_ACL_POLICY_ALLOW;
        builder->mode = LISTENER_ACL_MODE_ALLOW_EXCEPT;
    } else if (strcasecmp(policy, "deny_except") == 0) {
        if (global_acl_policy == GLOBAL_ACL_POLICY_ALLOW) {
            err("acl allow_except and deny_except stanzas are mutually exclusive");
            return 0;
        }
        global_acl_policy = GLOBAL_ACL_POLICY_DENY;
        builder->mode = LISTENER_ACL_MODE_DENY_EXCEPT;
    } else {
        err("Unknown ACL policy: %s", policy);
        return 0;
    }

    return 1;
}

static int
accept_listener_acl_cidr(struct ListenerACLBuilder *builder, const char *value) {
    struct ListenerACLRule *rule;

    if (builder == NULL || value == NULL)
        return 0;

    rule = new_listener_acl_rule_from_cidr(value);
    if (rule == NULL)
        return 0;

    SLIST_INSERT_HEAD(&builder->rules, rule, entries);
    return 1;
}

static int
end_listener_acl_stanza(struct Listener *listener, struct ListenerACLBuilder *builder) {
    if (listener == NULL || builder == NULL) {
        free_listener_acl_builder(builder);
        return 0;
    }

    if (listener->acl_mode != LISTENER_ACL_MODE_DISABLED ||
            !SLIST_EMPTY(&listener->acl_rules)) {
        err("Duplicate ACL definition for listener");
        free_listener_acl_builder(builder);
        return 0;
    }

    listener->acl_mode = builder->mode;
    listener->acl_rules = builder->rules;
    SLIST_INIT(&builder->rules);

    free_listener_acl_builder(builder);
    return 1;
}

static int
accept_username(struct Config *config, const char *username) {
    if (config->user != NULL) {
        err("Duplicate username: %s", username);
        return 0;
    }
    config->user = strdup(username);
    if (config->user == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
accept_groupname(struct Config *config, const char *groupname) {
    if (config->group != NULL) {
        err("Duplicate groupname: %s", groupname);
        return 0;
    }
    config->group = strdup(groupname);
    if (config->group == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
accept_pidfile(struct Config *config, const char *pidfile) {
    if (config->pidfile != NULL) {
        err("Duplicate pidfile: %s", pidfile);
        return 0;
    }
    config->pidfile = strdup(pidfile);
    if (config->pidfile == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
accept_per_ip_connection_rate(struct Config *config, const char *value) {
    char *endptr = NULL;
    double rate = strtod(value, &endptr);

    if (endptr == value || (endptr != NULL && *endptr != '\0')) {
        err("Unable to parse per_ip_connection_rate '%s'", value);
        return 0;
    }
    if (rate < 0.0) {
        err("per_ip_connection_rate must be non-negative: %s", value);
        return 0;
    }

    config->per_ip_connection_rate = rate;

    return 1;
}

static int
end_listener_stanza(struct Config *config, struct Listener *listener) {
    listener->accept_cb = &accept_connection;

    if (valid_listener(listener) <= 0) {
        err("Invalid listener");
        print_listener_config(stderr, listener);

        /* free listener */
        listener_ref_get(listener);
        assert(listener->reference_count == 1);
        listener_ref_put(listener);

        return -1;
    }

    add_listener(&config->listeners, listener);

    return 1;
}

static int
end_table_stanza(struct Config *config, struct Table *table) {
    if (valid_table(table) <= 0) {
        err("Invalid table");
        print_table_config(stderr, table);

        table_ref_get(table);
        assert(table->reference_count == 1);
        table_ref_put(table);

        return -1;
    }

    add_table(&config->tables, table);

    return 1;
}

static int
end_backend(struct Table *table, struct Backend *backend) {
    const char *table_name = table->name != NULL ? table->name : "(default)";

    if (!valid_backend(backend)) {
        err("Invalid backend in table \"%s\"", table_name);
        free_backend(backend);
        return -1;
    }

    table->use_proxy_header = table->use_proxy_header ||
                              backend->use_proxy_header;
    add_backend(&table->backends, backend);

    return 1;
}

static struct LoggerBuilder *
new_logger_builder(void) {
    struct LoggerBuilder *lb = malloc(sizeof(struct LoggerBuilder));
    if (lb == NULL) {
        err("%s: malloc", __func__);
        return NULL;
    }

    lb->filename = NULL;
    lb->syslog_facility = NULL;
    lb->priority = LOG_NOTICE;

    return lb;
}

static int
accept_logger_filename(struct LoggerBuilder *lb, const char *filename) {
    lb->filename = strdup(filename);
    if (lb->filename == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
accept_logger_syslog_facility(struct LoggerBuilder *lb, const char *facility) {
    lb->syslog_facility = strdup(facility);
    if (lb->syslog_facility == NULL) {
        err("%s: strdup", __func__);
        return -1;
    }

    return 1;
}

static int
accept_logger_priority(struct LoggerBuilder *lb, const char *priority) {
    const struct {
        const char *name;
        int priority;
    } priorities[] = {
        { "emergency",  LOG_EMERG },
        { "alert",      LOG_ALERT },
        { "critical",   LOG_CRIT },
        { "error",      LOG_ERR },
        { "warning",    LOG_WARNING },
        { "notice",     LOG_NOTICE },
        { "info",       LOG_INFO },
        { "debug",      LOG_DEBUG },
    };

    if (priority == NULL || *priority == '\0')
        return -1;

    size_t priority_len = strlen(priority);

    for (size_t i = 0; i < sizeof(priorities) / sizeof(priorities[0]); i++)
        if (strncasecmp(priorities[i].name, priority, priority_len) == 0) {
            lb->priority = priorities[i].priority;
            return 1;
        }

    return -1;
}

static int
end_error_logger_stanza(struct Config *config __attribute__ ((unused)), struct LoggerBuilder *lb) {
    struct Logger *logger = NULL;

    if (lb->filename != NULL && lb->syslog_facility == NULL)
        logger = new_file_logger(lb->filename);
    else if (lb->syslog_facility != NULL && lb->filename == NULL)
        logger = new_syslog_logger(lb->syslog_facility);
    else
        err("Logger can not be both file logger and syslog logger");

    if (logger == NULL) {
        free((char *)lb->filename);
        free((char *)lb->syslog_facility);
        free(lb);
        return -1;
    }

    set_logger_priority(logger, lb->priority);
    set_default_logger(logger);

    free((char *)lb->filename);
    free((char *)lb->syslog_facility);
    free(lb);
    return 1;
}

static int __attribute__((unused))
end_global_access_logger_stanza(struct Config *config, struct LoggerBuilder *lb) {
    struct Logger *logger = NULL;

    if (lb->filename != NULL && lb->syslog_facility == NULL)
        logger = new_file_logger(lb->filename);
    else if (lb->syslog_facility != NULL && lb->filename == NULL)
        logger = new_syslog_logger(lb->syslog_facility);
    else
        err("Logger can not be both file logger and syslog logger");

    if (logger == NULL) {
        free((char *)lb->filename);
        free((char *)lb->syslog_facility);
        free(lb);
        return -1;
    }

    set_logger_priority(logger, lb->priority);
    logger_ref_put(config->access_log);
    config->access_log = logger_ref_get(logger);

    free((char *)lb->filename);
    free((char *)lb->syslog_facility);
    free(lb);
    return 1;
}

static int
end_listener_access_logger_stanza(struct Listener *listener, struct LoggerBuilder *lb) {
    struct Logger *logger = NULL;

    if (lb->filename != NULL && lb->syslog_facility == NULL)
        logger = new_file_logger(lb->filename);
    else if (lb->syslog_facility != NULL && lb->filename == NULL)
        logger = new_syslog_logger(lb->syslog_facility);
    else
        err("Logger can not be both file logger and syslog logger");

    if (logger == NULL) {
        free((char *)lb->filename);
        free((char *)lb->syslog_facility);
        free(lb);
        return -1;
    }

    set_logger_priority(logger, lb->priority);
    logger_ref_put(listener->access_log);
    listener->access_log = logger_ref_get(logger);

    free((char *)lb->filename);
    free((char *)lb->syslog_facility);
    free(lb);
    return 1;
}

static struct ResolverConfig *
new_resolver_config(void) {
    struct ResolverConfig *resolver = malloc(sizeof(struct ResolverConfig));

    if (resolver != NULL) {
        resolver->nameservers = NULL;
        resolver->search = NULL;
        resolver->mode = 0;
        resolver->max_concurrent_queries = DEFAULT_DNS_QUERY_CONCURRENCY;
        resolver->dnssec_validation_mode = DNSSEC_VALIDATION_OFF;
    }

    return resolver;
}

static size_t
string_vector_len(char **vector) {
    size_t len = 0;
    while (vector != NULL && *vector++ != NULL)
        len++;

    return len;
}

static int
append_to_string_vector(char ***vector_ptr, const char *string) {
    char **vector = *vector_ptr;

    size_t len = string_vector_len(vector);
    vector = realloc(vector, (len + 2) * sizeof(char *));
    if (vector == NULL) {
        err("%s: realloc", __func__);
        return -errno;
    }

    *vector_ptr = vector;

    vector[len] = strdup(string);
    if (vector[len] == NULL) {
        err("%s: strdup", __func__);
        return -errno;
    }
    vector[len + 1] = NULL;

    return len + 1;
}

static void
free_string_vector(char **vector) {
    for (int i = 0; vector != NULL && vector[i] != NULL; i++) {
        free(vector[i]);
        vector[i] = NULL;
    }

    free(vector);
}

static int
accept_resolver_nameserver(struct ResolverConfig *resolver, const char *nameserver) {
    /* Validate address is a valid IP */
    struct Address *ns_address = new_address(nameserver);
    if (!address_is_sockaddr(ns_address)) {
        free(ns_address);
        return -1;
    }
    free(ns_address);

    return append_to_string_vector(&resolver->nameservers, nameserver);
}

static int
accept_resolver_search(struct ResolverConfig *resolver, const char *search) {
    struct Address *search_address = new_address(search);
    if (!address_is_hostname(search_address)) {
        free(search_address);
        return -1;
    }
    free(search_address);

    return append_to_string_vector(&resolver->search, search);
}

static int
accept_resolver_mode(struct ResolverConfig *resolver, const char *mode) {
    if (mode == NULL || *mode == '\0')
        return -1;

    size_t mode_len = strlen(mode);

    for (size_t i = 0; i < sizeof(resolver_mode_names) / sizeof(resolver_mode_names[0]); i++)
        if (strncasecmp(resolver_mode_names[i], mode, mode_len) == 0) {
            resolver->mode = i;
            return 1;
        }

    return -1;
}

static int
accept_resolver_dnssec_validation(struct ResolverConfig *resolver, const char *value) {
    if (value == NULL || *value == '\0')
        return -1;

    if (strcasecmp(value, "off") == 0 || strcasecmp(value, "no") == 0 ||
            strcasecmp(value, "false") == 0 || strcasecmp(value, "disable") == 0 ||
            strcasecmp(value, "disabled") == 0) {
        resolver->dnssec_validation_mode = DNSSEC_VALIDATION_OFF;
        return 1;
    }

    if (strcasecmp(value, "relaxed") == 0 || strcasecmp(value, "allow_insecure") == 0 ||
            strcasecmp(value, "permissive") == 0 || strcasecmp(value, "fail_open") == 0 ||
            strcasecmp(value, "fail-open") == 0) {
        resolver->dnssec_validation_mode = DNSSEC_VALIDATION_RELAXED;
        return 1;
    }

    if (strcasecmp(value, "strict") == 0 || strcasecmp(value, "require") == 0 ||
            strcasecmp(value, "enforce") == 0 || strcasecmp(value, "on") == 0 ||
            strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0) {
        resolver->dnssec_validation_mode = DNSSEC_VALIDATION_STRICT;
        return 1;
    }

    err("Unknown dnssec_validation mode '%s'", value);
    return -1;
}

static int
accept_resolver_max_queries(struct ResolverConfig *resolver, const char *value) {
    if (value == NULL || *value == '\0')
        return -1;

    char *endptr = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &endptr, 10);

    if (errno != 0 || endptr == value || *endptr != '\0')
        return -1;

    if (parsed == 0)
        return -1;

    if (parsed > SIZE_MAX)
        return -1;

    resolver->max_concurrent_queries = (size_t)parsed;
    return 1;
}

static int
end_resolver_stanza(struct Config *config, struct ResolverConfig *resolver) {
    config->resolver = *resolver;
    free(resolver);

    return 1;
}

static void
print_resolver_config(FILE *file, struct ResolverConfig *resolver) {
    fprintf(file, "resolver {\n");

    for (int i = 0; resolver->nameservers != NULL && resolver->nameservers[i] != NULL; i++)
        fprintf(file, "\tnameserver %s\n", resolver->nameservers[i]);

    for (int i = 0; resolver->search != NULL && resolver->search[i] != NULL; i++)
        fprintf(file, "\tsearch %s\n", resolver->search[i]);

    fprintf(file, "\tmode %s\n", resolver_mode_names[resolver->mode]);
    fprintf(file, "\tmax_concurrent_queries %zu\n", resolver->max_concurrent_queries);
    fprintf(file, "\tdnssec_validation %s\n",
            dnssec_validation_mode_names[resolver->dnssec_validation_mode]);

    fprintf(file, "}\n\n");
}
