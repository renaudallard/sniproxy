AM_CPPFLAGS = -I$(top_srcdir)/src -g $(LIBEV_CFLAGS) $(PCRE2_CFLAGS) $(HARDEN_CPPFLAGS)
AM_CFLAGS = -fno-strict-aliasing -Wall -Wextra -Wpedantic -Wwrite-strings $(HARDEN_CFLAGS) $(SANITIZER_CFLAGS)
AM_LDFLAGS = $(HARDEN_LDFLAGS) $(SANITIZER_LDFLAGS)

.NOTPARALLEL:

TESTS = address_test \
        buffer_test \
        cfg_tokenizer_test \
        table_test \
        http_test \
        tls_test \
        xmpp_test \
        binder_test \
        seccomp_test

TESTS += functional_test \
         bad_request_test \
         bind_source_test \
         connection_reset_test \
         fallback_test \
         fd_limit_test \
         ipv6_v6only_test \
         proxy_header_test \
         reload_test \
         reuseport_test \
         slow_client_test \
         transparent_proxy_test
TESTS += config_test \
         resolv_test \
         bad_dns_request_test

check_PROGRAMS = http_test \
                 tls_test \
                 xmpp_test \
                 table_test \
                 binder_test \
                 buffer_test \
                 cfg_tokenizer_test \
                 address_test \
                 resolv_test \
                 config_test \
                 seccomp_test

http_test_SOURCES = http_test.c \
                    ../src/http.c \
                    ../src/http2.c \
                    ../src/http2_huffman.c

tls_test_SOURCES = tls_test.c \
                   ../src/tls.c \
                   ../src/logger.c \
                   ../src/ipc_crypto.c \
                   ../src/seccomp.c

tls_test_LDADD = -lssl $(LIBCRYPTO_LIBS) $(LIBSECCOMP_LIBS)

xmpp_test_SOURCES = xmpp_test.c \
                    ../src/xmpp.c

binder_test_SOURCES = binder_test.c \
                      ../src/binder.c \
                      ../src/logger.c \
                      ../src/ipc_crypto.c \
                      ../src/seccomp.c

binder_test_LDADD = $(LIBSECCOMP_LIBS)

buffer_test_SOURCES = buffer_test.c \
                      ../src/buffer.c

buffer_test_LDADD = $(LIBEV_LIBS)

address_test_SOURCES = address_test.c \
                      ../src/address.c

cfg_tokenizer_test_SOURCES = cfg_tokenizer_test.c \
                             ../src/cfg_tokenizer.c

config_test_SOURCES = config_test.c \
                      ../src/binder.c \
                      ../src/config.c \
                      ../src/cfg_parser.c \
                      ../src/cfg_tokenizer.c \
                      ../src/address.c \
                      ../src/backend.c \
                      ../src/table.c \
                      ../src/listener.c \
                      ../src/connection.c \
                      ../src/buffer.c \
                      ../src/logger.c \
                      ../src/ipc_crypto.c \
                      ../src/resolv.c \
                      ../src/resolv.h \
                      ../src/tls.c \
                      ../src/http.c \
                      ../src/http2.c \
                      ../src/http2_huffman.c \
                      ../src/xmpp.c \
                      ../src/seccomp.c

config_test_LDADD = $(LIBEV_LIBS) $(PCRE2_LIBS) -lssl $(LIBCRYPTO_LIBS) $(LIBSECCOMP_LIBS)

resolv_test_SOURCES = resolv_test.c \
                      ../src/resolv.c \
                      ../src/address.c \
                      ../src/logger.c \
                      ../src/ipc_crypto.c \
                      ../src/seccomp.c

resolv_test_LDADD = $(LIBEV_LIBS) -lssl $(LIBCRYPTO_LIBS) $(LIBSECCOMP_LIBS)

table_test_SOURCES = table_test.c \
                      ../src/backend.c \
                      ../src/table.c \
                      ../src/address.c \
                      ../src/logger.c \
                      ../src/ipc_crypto.c \
                      ../src/seccomp.c

table_test_LDADD = $(PCRE2_LIBS) $(LIBSECCOMP_LIBS)

seccomp_test_SOURCES = seccomp_test.c \
                       ../src/seccomp.c

seccomp_test_LDADD = $(LIBSECCOMP_LIBS) -lpthread
