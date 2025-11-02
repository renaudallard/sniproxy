AM_CFLAGS = -fno-strict-aliasing -Wall -Wextra -Wpedantic -Wwrite-strings
AM_CPPFLAGS =

sbin_PROGRAMS = sniproxy

sniproxy_SOURCES = sniproxy.c \
                   address.c \
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

sniproxy_LDADD =

if HTTP3_ENABLED
AM_CPPFLAGS += $(QUICHE_CFLAGS) $(HAVE_QUICHE_DEFINE)
sniproxy_SOURCES += quic.c \
                   quic.h \
                   quic_listener.c \
                   quic_listener.h
sniproxy_LDADD += $(QUICHE_LIBS)
endif

EXTRA_DIST = quic.c quic.h quic_listener.c quic_listener.h
