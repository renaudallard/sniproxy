Name: sniproxy
Version: 0.9.12
Release: 1%{?dist}
Summary: Transparent TLS and HTTP layer 4 proxy with SNI support

Group: System Environment/Daemons
License: BSD
URL: https://github.com/dlundquist/sniproxy
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf, automake, curl, libev-devel, pcre2-devel, gettext-devel, c-ares-devel, systemd-rpm-macros

%description
Proxies incoming HTTP and TLS connections based on the hostname contained in
the initial request of the TCP session. This enables HTTPS name-based virtual
hosting to separate backend servers without installing the private key on the
proxy machine.


%prep
%setup -q


%build
%configure CFLAGS="%{optflags} -I/usr/include/libev"
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
install -D -m 0644 scripts/sniproxy.service $RPM_BUILD_ROOT%{_unitdir}/sniproxy.service


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_sbindir}/sniproxy
%doc
%{_mandir}/man8/sniproxy.8.gz
%{_mandir}/man5/sniproxy.conf.5.gz
%{_unitdir}/sniproxy.service

%post
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl --no-reload --quiet stop sniproxy.service 2>/dev/null || :
fi

%postun
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi



%changelog
* Mon Nov 24 2025 Renaud Allard <renaud@allard.it> 0.9.12-1
- Build: rpmbuild now preserves %{optflags} while appending the libev include
  path, drops the unused perl BuildRequires, and the release-packages workflow
  can be run manually to generate RPM/DEB artifacts on demand.
- Packaging: distribution tarballs ship the missing hostname_sanitize.h so
  builds from released archives no longer fail, and the %{_bindir}/sniproxy
  wrapper is removed so only the real daemon is installed.
- Tests: Added a resolver response fuzz harness, exposed fuzz-only resolver
  helpers, expanded the libev stub to cover timers/signals/loop lifecycle, and
  fixed a leak in the resolver fuzz harness to keep fuzz runs stable.

* Sun Nov 23 2025 Renaud Allard <renaud@allard.it> 0.9.11-1
- Security: HTTP parsing now enforces a configurable http_max_headers limit,
  TLS ClientHello parsing bounds extension counts up front, and ipc_crypto
  failure paths perform dummy decrypts with dedicated zero_tag buffers to
  mask timing when packets are rejected.
- Configuration: all absolute-path directives are canonicalized and the parser
  gained typed cleanup hooks so resolver/log/logger/listener contexts free
  their previous allocations on error; the long-deprecated sniproxy-cfg helper
  and man page were removed to avoid shipping a stale binary.
- Tooling/Tests: ship a hardened scripts/sniproxy.service template, drop the
  sniproxy wrapper so only %{_sbindir}/sniproxy is installed everywhere, add
  RPM/DEB builds to the release workflow, and expand the fuzz suite with
  address/table/listener ACL/ipc harnesses that default to error-only logs,
  while dropping the unused perl BuildRequires so rpmbuild no longer depends
  on perl just to assemble the package.

* Sat Nov 22 2025 Renaud Allard <renaud@allard.it> 0.9.10-1
- Security: get_secure_temp_dir() now runs lstat() checks for /var/run and
  /tmp fallbacks before opening directories with O_NOFOLLOW, preventing
  attacker-supplied symlinks.
- Robustness: Unix socket address parsing forcibly null-terminates sun_path
  and cfg_tokenizer always null-terminates buffers before returning errors.
- DNS: Configuration reloads propagate the per-client DNS concurrency limit
  alongside the global cap so throttles stay aligned.

* Fri Nov 21 2025 Renaud Allard <renaud@allard.it> 0.9.9-1
- Security: PROXY header generation now enforces buffer space, logs clients
  when the header cannot be appended, and refuses to forward; sockaddr parsing
  clamps copy_sockaddr_to_storage, validates sa_len, and backend caches reject
  lengths that would overflow allocations.
- Networking: Per-client DNS concurrency limits complement the global cap,
  defaults now sit at 16 per client and 512 overall, both caps can be tuned via
  resolver max_concurrent_queries(_per_client), and the address parser handles
  trailing ports via centralized logic with bounded recursion.
- Crypto: ipc_crypto_seal validates header/tag overhead, blocks SIZE_MAX-length
  frames, and halts when the send counter reaches UINT64_MAX, while derive_key
  rejects HKDF labels over 1024 bytes.
- Reliability: Buffer helpers assert read/write offsets never exceed capacity
  and setup_write_iov stops when a buffer reports an impossible length.

* Thu Nov 20 2025 Renaud Allard <renaud@allard.it> 0.9.8-1
- Security: remove legacy PCRE1 fallback, require libpcre2 everywhere, and
  harden fuzz/test builds with explicit PCRE2 detection.
- Security: configuration reloads now re-validate file permissions, temporary
  connection dumps use `mkostemp` with CLOEXEC/NOFOLLOW, HKDF buffers zeroize
  and reject oversized labels, and resolver cancellation adds a memory fence.
- Hardening: enforce absolute config paths and treat resolver search domains as
  literal suffixes without hostname validation.
- Build/docs: README, architecture notes, Debian/RPM metadata, and tools all
  reflect the libpcre2 requirement.
- Networking: resolver blocks can now specify DNS-over-TLS upstreams via
  `dot://address/hostname` entries with certificate validation.

* Wed Nov 19 2025 Renaud Allard <renaud@allard.it> 0.9.7-1
- DNS: enable DNSSEC validation in relaxed mode by default so wildcard tables
  and fallback targets benefit from authenticated data without manual config.
- Security: sniproxy now refuses to load config files that are
  group/world accessible by checking permissions on the opened descriptor,
  covering both startup and reload paths.
- Documentation: README and man pages now describe the new DNSSEC default and
  stricter configuration-permission requirements.

* Tue Nov 18 2025 Renaud Allard <renaud@allard.it> 0.9.6-1
- Security: strengthen per-IP rate limiting with FNV-1a hashing, collision
  cutoffs, and strict HTTP header/TLS extension caps plus IPC payload limits.
- DNS: arc4random() query IDs, mutex-guarded restarts, and query handle
  assertions prevent leaks and use-after-free bugs.
- Reliability: shrink candidate queues cap at 4096 entries with active trimming,
  buffer growth failures now close connections, and log duration math clamps
  negatives from time jumps.
- Hardening: secure_memzero, PID file sanity checks, and buffer pool magic
  numbers detect corruption before dereferencing nodes.

* Sat Nov 15 2025 Renaud Allard <renaud@allard.it> 0.9.5-1
- Performance: cache ev_now and add hysteresis to idle timers and buffer growth
- Reliability: resolver crash handler avoids spurious write warnings
- CI: fuzz workflow auto-selects clang/libFuzzer toolchains with better diagnostics

* Fri Nov 14 2025 Renaud Allard <renaud@allard.it> 0.9.4-1
- Security: configs with group/world permissions now abort startup
- Resource: per-connection buffer limits added
- IPC: helper children no longer inherit unintended fds

* Wed Nov 12 2025 Renaud Allard <renaud@allard.it> 0.9.3-1
- Fail hard when privilege dropping does not remove root privileges
- Warn when configuration files are readable or executable by group/others

* Mon Nov 10 2025 Renaud Allard <renaud@allard.it> 0.9.2-1
- Harden resolver restarts and keep pending DNS queries alive
- Restart binder helper on IPC failures and fix partial read handling
- Retry outbound connects on transient EADDRNOTAVAIL errors

* Sun Nov 9 2025 Renaud Allard <renaud@allard.it> 0.9.1-1
- Prepare 0.9.1 release

* Sat Nov 8 2025 Renaud Allard <renaud@allard.it> 0.9.0-1
- Major performance and security release
- Security: DNS query IDs use PRNG (xorshift32) instead of linear counter
- Security: c-ares resolver hardening (async-signal-safe, integer overflow protection)
- Security: TLS parser improvements (reject invalid ClientHello variants)
- Performance: Per-backend pattern match caching (skip repeated PCRE2 evaluations)
- Performance: HTTP/2 HPACK optimization (precomputed lengths, binary search)
- Performance: Optimized buffer shrink decisions (periodic timer)
- Performance: Connection memory tracking and accounting
- Performance: Rate limit hash table optimization (IPv4 fast path, LRU)
- Performance: Protocol parser optimizations (TLS, HTTP, HTTP/2)
- Performance: PROXY v1 header composition optimization

* Thu Sep 4 2025 Renaud Allard <renaud@allard.it> 0.8.6-1
- Prepare 0.8.6 release

* Wed Sep 4 2024 Dustin Lundquist <dustin@null-ptr.net> 0.7.0-1
- Deprecate project
- Cleanup autoconf
- Require autoconf 2.71
- Require explicit --enable-dns for DNS resolution functionality
- Add support for libpcre2 as an alternative to the older libpcre3
- Relax HTTP header parsing to accept CRLF or plain LF
- Fix missing stdlib.h include
- Fix various warnings reported by gcc 14 and clang 19 compilers

* Thu Mar 16 2023 Dustin Lundquist <dustin@null-ptr.net> 0.6.1-1
- Fix buffer overflow in address module
- Fix tests

* Wed Dec 5 2018 Dustin Lundquist <dustin@null-ptr.net> 0.6.0-1
- PROXY v1 protocol support
- SO_REUSEPORT support on Linux 3.9 and later
- Listener ipv6_only directive to accept only IPv6 connections
- TCP keepalive

* Wed Apr 26 2017 Dustin Lundquist <dustin@null-ptr.net> 0.5.0-1
- Transparent proxy support
- Use accept4() on Linix
- Run as group specified in config

* Tue Apr 7 2015 Dustin Lundquist <dustin@null-ptr.net> 0.4.0-1
- Improve DNS resolver:
  Support for AAAA records
  Configuration options
- Global access log
- Man page for sniproxy.conf
- Reject IP literals as hostnames for wildcard backends

* Fri Sep 26 2014 Dustin Lundquist <dustin@null-ptr.net> 0.3.6-1
- Improve logging:
  Fix negative connection duration in access log
  Include log rotate script
  Reopen log files on SIGHUP
  Share file handle to same log file between listeners
  Avoid unnecessary reconnection to syslog socket
  Cache timestamp string for current second
- Man page
- Packaging improvements:
  passes lintian and rpm-lint

* Wed Aug 13 2014 Dustin Lundquist <dustin@null-ptr.net> 0.3.5-1
- Configuration reloading on SIGHUP
- SSL 2.0 connection handling: do not treat as an error, use fallback
  address if configured.
- Fix buffer_coalesce error
- Spawn privileged child to bind sockets to privileged ports on reload
- Add -V flag to return sniproxy version
- Use libev for timestamps to improve portability
- Include several for BSD compatibility
- Large file support (for log files)
