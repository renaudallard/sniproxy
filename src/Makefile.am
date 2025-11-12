AM_CFLAGS = -fno-strict-aliasing -Wall -Wextra -Wpedantic -Wwrite-strings

sbin_PROGRAMS = sniproxy sniproxy-cfg

sniproxy_common_sources = address.c \
                          address.h \
                          backend.c \
                          backend.h \
                          binder.c \
                          binder.h \
                          buffer.c \
                          buffer.h \
                          cfg_parser.c \
                          cfg_parser.h \
                          cfg_tokenizer.c \
                          cfg_tokenizer.h \
                          config.c \
                          config.h \
                          connection.c \
                          connection.h \
                          http.c \
                          http.h \
                          http2.c \
                          http2.h \
                          http2_huffman.c \
                          http2_huffman.h \
                          http2_huffman_table.inc \
                          ipc_crypto.c \
                          ipc_crypto.h \
                          fd_util.h \
                          listener.c \
                          listener.h \
                          logger.c \
                          logger.h \
                          protocol.h \
                          resolv.c \
                          resolv.h \
                          table.c \
                          table.h \
                          tls.c \
                          tls.h

sniproxy_SOURCES = sniproxy.c \
                   $(sniproxy_common_sources)

sniproxy_cfg_SOURCES = config_validator.c \
                              $(sniproxy_common_sources)
