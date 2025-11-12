bin_SCRIPTS = sniproxy
EXTRA_DIST = sniproxy.in
CLEANFILES = $(bin_SCRIPTS)

sniproxy: sniproxy.in Makefile
	$(AM_V_GEN)sed -e 's|@sbindir@|$(sbindir)|g' $(srcdir)/sniproxy.in > $@ && chmod +x $@
