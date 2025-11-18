#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([sniproxy],[0.9.7])
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AC_USE_SYSTEM_EXTENSIONS

AC_DEFUN([SNIPROXY_APPEND_CFLAG], [
  AS_VAR_PUSHDEF([cachevar], [sniproxy_cv_cflag_$2])
  AC_CACHE_CHECK([whether $CC supports $1], cachevar, [
    sniproxy_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $1"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[return 0;]])],
      [AS_VAR_SET(cachevar, [yes])],
      [AS_VAR_SET(cachevar, [no])])
    CFLAGS="$sniproxy_save_CFLAGS"
  ])
  AS_IF([test "x"AS_VAR_GET(cachevar) = xyes], [
    HARDEN_CFLAGS="$HARDEN_CFLAGS $1"
  ])
  AS_VAR_POPDEF([cachevar])
])

AC_DEFUN([SNIPROXY_APPEND_CPPFLAG], [
  AS_VAR_PUSHDEF([cachevar], [sniproxy_cv_cppflag_$2])
  AC_CACHE_CHECK([whether the compiler accepts $1], cachevar, [
    sniproxy_save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $1"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[return 0;]])],
      [AS_VAR_SET(cachevar, [yes])],
      [AS_VAR_SET(cachevar, [no])])
    CPPFLAGS="$sniproxy_save_CPPFLAGS"
  ])
  AS_IF([test "x"AS_VAR_GET(cachevar) = xyes], [
    HARDEN_CPPFLAGS="$HARDEN_CPPFLAGS $1"
  ])
  AS_VAR_POPDEF([cachevar])
])

AC_DEFUN([SNIPROXY_APPEND_LDFLAG], [
  AS_VAR_PUSHDEF([cachevar], [sniproxy_cv_ldflag_$2])
  AC_CACHE_CHECK([whether the linker accepts $1], cachevar, [
    sniproxy_save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS $1"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [[return 0;]])],
      [AS_VAR_SET(cachevar, [yes])],
      [AS_VAR_SET(cachevar, [no])])
    LDFLAGS="$sniproxy_save_LDFLAGS"
  ])
  AS_IF([test "x"AS_VAR_GET(cachevar) = xyes], [
    HARDEN_LDFLAGS="$HARDEN_LDFLAGS $1"
  ])
  AS_VAR_POPDEF([cachevar])
])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening], [Disable compiler and linker hardening flags])],
  [enable_hardening=$enableval],
  [enable_hardening=yes])

HARDEN_CFLAGS=""
HARDEN_CPPFLAGS=""
HARDEN_LDFLAGS=""

AS_IF([test "x$enable_hardening" != "xno"], [
  SNIPROXY_APPEND_CPPFLAG([-U_FORTIFY_SOURCE], [u_fortify_source])
  SNIPROXY_APPEND_CPPFLAG([-D_FORTIFY_SOURCE=2], [fortify_source])
  SNIPROXY_APPEND_CFLAG([-fstack-protector-strong], [fstack_protector_strong])
  SNIPROXY_APPEND_CFLAG([-fstack-clash-protection], [fstack_clash_protection])
  SNIPROXY_APPEND_CFLAG([-fcf-protection=full], [fcf_protection])
  SNIPROXY_APPEND_CFLAG([-Wformat], [wformat])
  SNIPROXY_APPEND_CFLAG([-Wformat-security], [wformat_security])
  SNIPROXY_APPEND_CFLAG([-Werror=format-security], [werror_format_security])
  SNIPROXY_APPEND_CFLAG([-fPIE], [fpie])
  SNIPROXY_APPEND_LDFLAG([-Wl,-z,relro], [ld_relro])
  SNIPROXY_APPEND_LDFLAG([-Wl,-z,now], [ld_now])
  SNIPROXY_APPEND_LDFLAG([-Wl,-z,noexecstack], [ld_noexecstack])
  SNIPROXY_APPEND_LDFLAG([-Wl,-z,separate-code], [ld_separate_code])
  SNIPROXY_APPEND_LDFLAG([-pie], [ld_pie])
], [
  AC_MSG_WARN([Compiler/linker hardening disabled])
])

AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_CPPFLAGS])
AC_SUBST([HARDEN_LDFLAGS])

# Checks for libraries.
AC_CHECK_LIB([ev], [ev_run], [],
	     [AC_MSG_ERROR([libev is required])])
AC_CHECK_LIB([pcre2-8], [pcre2_compile_8], [],
	     [AC_MSG_ERROR([libpcre2 is required])])
PCRE2_LIBS='-lpcre2-8'
PCRE2_CFLAGS=''
AC_SUBST([PCRE2_LIBS])
AC_SUBST([PCRE2_CFLAGS])

AC_CHECK_HEADERS([ares.h], [],
  [AC_MSG_ERROR([c-ares headers are required])])
AC_CHECK_HEADERS([ares_dns.h], [],
  [AC_MSG_ERROR([c-ares addrinfo headers are required])])
AC_CHECK_LIB([cares], [ares_library_init], [],
  [AC_MSG_ERROR([c-ares is required])])

AC_CHECK_HEADERS([openssl/evp.h openssl/rand.h openssl/sha.h], [],
  [AC_MSG_ERROR([OpenSSL/LibreSSL headers with ChaCha20-Poly1305 are required])])
AC_CHECK_LIB([crypto], [EVP_chacha20_poly1305], [],
  [AC_MSG_ERROR([libcrypto with ChaCha20-Poly1305 is required])])
LIBCRYPTO_LIBS='-lcrypto'
AC_SUBST([LIBCRYPTO_LIBS])

AC_ARG_ENABLE([rfc3339-timestamps],
  [AS_HELP_STRING([--enable-rfc3339-timestamps], [Enable RFC3339 timestamps])],
  [AC_DEFINE([RFC3339_TIMESTAMP], 1, [RFC3339 timestamps enabled])])

AC_CHECK_FUNCS([accept4 daemon setproctitle mkostemp])

# Enable large file support (so we can log more than 2GB)
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 man/Makefile
                 tests/Makefile
                 scripts/Makefile])

AC_OUTPUT
