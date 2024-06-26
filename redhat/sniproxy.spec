Name: sniproxy
Version: 0.6.8
Release: 1%{?dist}
Summary: Transparent TLS and HTTP layer 4 proxy with SNI support

Group: System Environment/Daemons
License: BSD
URL: https://github.com/renaudallard/sniproxy
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf, automake, curl, libev-devel, pcre-devel, perl, gettext-devel, udns-devel

%description
Proxies incoming HTTP and TLS connections based on the hostname contained in
the initial request of the TCP session. This enables HTTPS name-based virtual
hosting to separate backend servers without installing the private key on the
proxy machine.


%prep
%setup -q


%build
%configure CFLAGS="-I/usr/include/libev"
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_sbindir}/sniproxy
%doc
%{_mandir}/man8/sniproxy.8.gz
%{_mandir}/man5/sniproxy.conf.5.gz

%changelog
* Tue, 31 Jan 2023 Renaud Allard <renaud@allard.it> 0.6.8
- Fix buffer overflow in address module
- Fix tests in Debian 11
* Tue, 31 Jan 2023 Renaud Allard <renaud@allard.it> 0.6.7
- Fix a warning with clang15 and update old functions
* Mon, 30 Jan 2023 Renaud Allard <renaud@allard.it> 0.6.6
- Print proper unveil errors (no influence for linux)
* Mon, 11 Mar 2021 Renaud Allard <renaud@allard.it> 0.6.5
- Add cpath and unix to plegde call for OpenBSD
- Add unveil protections for OpenBSD
- Remove -Wpedantic as it fails on OpenBSD base-gcc

* Mon, 01 Mar 2021 Renaud Allard <renaud@allard.it> 0.6.4
- Add wpath and unix to plegde call for OpenBSD
- fix ipv6 transparent proxy

* Wed, 24 Feb 2021 Renaud Allard <renaud@allard.it> 0.6.3
- Accept CRLF and LF in HTTP headers, fix buffer overflow error
- Add plegde call for OpenBSD

* Sat 22 Feb 2021 Renaud Allard <renaud@allard.it> 0.6.2
- Change the default user/group

* Sat 22 Feb 2021 Renaud Allard <renaud@allard.it> 0.6.1
- Fixes for some security issues
- Fix for compilation with modern compilers

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
