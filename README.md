<p align="center">
  <img src="sniproxy-banner-dark.svg" alt="sniproxy: hardened SNI routing" width="640"/>
</p>

<h3 align="center">Hardened SNI Proxy</h3>

<p align="center">
  <em>Route HTTP, TLS, DTLS, XMPP and Minecraft connections by hostname, without decrypting traffic.</em>
</p>

<p align="center">
  <a href="https://github.com/renaudallard/sniproxy/releases/latest">
    <img src="https://img.shields.io/github/v/release/renaudallard/sniproxy?label=version&style=flat-square&sort=semver" alt="Latest release"/>
  </a>
  <a href="https://github.com/renaudallard/sniproxy/releases">
    <img src="https://img.shields.io/github/downloads/renaudallard/sniproxy/total?style=flat-square&label=downloads" alt="Downloads"/>
  </a>
  <a href="https://github.com/renaudallard/sniproxy/actions/workflows/build-and-fuzz.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/renaudallard/sniproxy/build-and-fuzz.yml?style=flat-square&label=build%20%26%20fuzz" alt="Build and Fuzz"/>
  </a>
  <a href="https://github.com/renaudallard/sniproxy/actions/workflows/sanitizers.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/renaudallard/sniproxy/sanitizers.yml?style=flat-square&label=sanitizers" alt="Sanitizers"/>
  </a>
  <a href="https://github.com/renaudallard/sniproxy/actions/workflows/valgrind.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/renaudallard/sniproxy/valgrind.yml?style=flat-square&label=valgrind" alt="Valgrind"/>
  </a>
  <a href="https://github.com/renaudallard/sniproxy/actions/workflows/continuous-fuzzing.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/renaudallard/sniproxy/continuous-fuzzing.yml?style=flat-square&label=continuous%20fuzzing" alt="Continuous Fuzzing"/>
  </a>
  <a href="./COPYING">
    <img src="https://img.shields.io/github/license/renaudallard/sniproxy?style=flat-square" alt="License"/>
  </a>
  <a href="https://www.paypal.me/RenaudAllard">
    <img src="https://img.shields.io/badge/PayPal-Donate-blue.svg?logo=paypal&style=flat-square" alt="PayPal"/>
  </a>
</p>

---

SNIProxy inspects the **first packet** of an inbound connection, extracts the
client-requested hostname (SNI for TLS/DTLS, `Host` for HTTP, `:authority` for
HTTP/2, the stream `to` attribute for XMPP, the handshake server address for
Minecraft), and forwards the connection to a backend selected by hostname
pattern. The encrypted payload is **never decrypted**, so no private key
material is ever installed on the proxy host. This makes name-based virtual
hosting work for HTTPS the same way it does for HTTP.

The fork is a hardened, production-oriented continuation of the original
sniproxy by Dustin Lundquist, with privilege separation, encrypted IPC,
per-platform sandboxing (pledge/unveil, Capsicum, seccomp), continuous
fuzzing, and active maintenance.

> Primary platform: **OpenBSD**. Best-effort support on Linux, FreeBSD and macOS.

## Highlights

- **Name-based proxying without decryption**: TLS/DTLS SNI, HTTP/1 Host,
  HTTP/2 HPACK `:authority`, XMPP stream `to`, Minecraft handshake. No
  certificates or private keys on the proxy.
- **Five protocols, one binary**: TLS, DTLS (UDP), HTTP/1 + HTTP/2, XMPP
  (with STARTTLS), Minecraft Java Edition (FML and BungeeCord markers
  ignored when routing).
- **Pattern matching**: exact hostnames or PCRE2 (JIT-compiled where
  available), per-table backend selection with optional client-IP affinity.
- **Wildcard backends**: route to the dynamically resolved hostname the
  client asked for (`*:443`).
- **HAProxy PROXY protocol**: emit v1 or v2 headers to backends; accept v1
  or v2 from upstream load balancers on listeners with
  `proxy_protocol on` (the version is auto-detected).
- **Privilege separation**: four cooperating processes:
  `sniproxy-mainloop`, `sniproxy-binder`, `sniproxy-logger`,
  `sniproxy-resolver`. All IPC is encrypted with ChaCha20-Poly1305.
- **Per-platform sandboxing**: pledge(2) + unveil(2) on OpenBSD, Capsicum
  capability mode on FreeBSD, seccomp BPF on Linux.
- **DTLS source check**: a new UDP session is held until a second
  datagram arrives from the same source address and port before any
  backend traffic is sent, so a single spoofed packet reaches no backend.
- **Per-IP rate limiting**: token buckets in a hash table keyed with an
  arc4random seed cap new TCP connections and UDP sessions; short-chain
  cutoffs defeat hash spraying.
- **Backend ACLs**: `deny_except` or `allow_except` CIDR policies stop
  abuse as an open proxy to reach internal hosts.
- **Listener ACLs**: the same CIDR policies, applied to inbound clients.
- **DNS-over-TLS upstreams**: `nameserver dot://9.9.9.9/dns.quad9.net/tls1.2`
  inside the `resolver` block; IP literals require a TLS hostname or an
  explicit `/insecure`. TLS 1.2 is enforced by default.
- **Hot reload**: SIGHUP re-reads the config and updates listeners and
  tables in place without dropping live connections; connections that
  are already routed keep their backend. Hostname backends are resolved
  for every new connection, so DNS changes need no reload.
- **Zero-copy on OpenBSD**: SO_SPLICE moves data in the kernel after the
  handshake is parsed, user buffers shrink to 4 KiB and the idle timer
  checks the kernel byte counters, so one silent direction does not end
  a live connection.
- **Bounded memory**: per-connection buffer caps, a global soft limit
  that aggressively trims idle buffers, and a 4096-entry shrink queue stop
  slow clients from pinning unbounded RAM.
- **Continuous fuzzing**: dedicated harnesses for TLS, DTLS, HTTP/1,
  HTTP/2, XMPP, Minecraft, hostname, address, config, config tokenizer,
  table lookup, listener ACL, IPC crypto, IPC messages, IPC state and
  resolver responses run in CI and on a separate continuous-fuzzing job.

## Protocol support

| Protocol | Hostname source | Notes |
| --- | --- | --- |
| TLS 1.0&ndash;1.3 | SNI extension in ClientHello | TLS 1.2+ enforced by default; `-T 1.0/1.1/1.2/1.3` overrides |
| DTLS | SNI extension in UDP ClientHello | Session held until a second datagram arrives from the same source |
| HTTP/1.x | `Host:` request header | Header count capped by `http_max_headers` (default 100) |
| HTTP/2 | HPACK `:authority` pseudo-header | Bounded HPACK table (per-conn 64 KiB / global 4 MiB) |
| XMPP | `to` attribute on `<stream:stream>` | STARTTLS negotiation passes through untouched |
| Minecraft (Java Edition) | Server address in handshake packet | FML and BungeeCord NUL-delimited trailers ignored when routing, forwarded unchanged |

## Architecture

SNIProxy runs as four cooperating processes:

1. **`sniproxy-mainloop`**: accepts connections, parses the first protocol
   header, picks a backend and forwards bidirectionally.
2. **`sniproxy-binder`**: keeps root so that a listener added by a
   SIGHUP reload can still bind a privileged port once the main loop has
   dropped its privileges; the initial listeners are bound by the main
   loop before it drops root. It idles otherwise, and only binds Unix
   socket paths under `/run` or `/var/run`.
3. **`sniproxy-logger`**: writes the log files. The main loop sends it
   log lines over an encrypted, authenticated Unix socket.
4. **`sniproxy-resolver`**: runs c-ares for async DNS and DNS-over-TLS.
   The main loop caps the queries in flight, overall and per client, and
   restarts the resolver if it exits.

All IPC channels are encrypted with ChaCha20-Poly1305. The master key is
generated and locked in memory once in the parent and inherited across
`fork()`, and each channel's keys are derived from it with a fresh salt
when its child starts, so children never have to read key material from
disk or call `mlock()` after `pledge()`. The logger drops root once the
listeners are bound and the resolver is started after that, so both run
unprivileged; the binder keeps root, which is its purpose. On a platform
that provides one (pledge/unveil, Capsicum, or seccomp), each process
enters its sandbox before it handles client traffic; the FreeBSD
exceptions are listed under Installation.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and process
boundaries, and [SANITIZERS.md](SANITIZERS.md) for how to build under
ASan/MSan/UBSan/TSan.

## Quick start

```nginx
user daemon
group daemon

pidfile /var/run/sniproxy.pid

error_log {
    filename /var/log/sniproxy/error.log
    priority notice
}

listener 0.0.0.0:443 {
    protocol tls
    table https_hosts

    # Used when the ClientHello has no usable SNI, cannot be parsed, or
    # names a host that matches no table entry
    fallback 192.0.2.50:443

    access_log {
        filename /var/log/sniproxy/access.log
    }
}

table https_hosts {
    # Exact host. Bare hostnames are auto-anchored, so this matches
    # "example.com" only, never "sub.example.com".
    example.com         192.0.2.10:443

    # PCRE2 regular expression. The config parser consumes one
    # backslash, so double them, and end with $: a regex is not
    # anchored and would also match "example.net.attacker.org".
    .*\\.example\\.net$     192.0.2.11:443

    # Wildcard backend: connect to whatever the client asked for
    .*\\.cdn\\.example$     *:443
}
```

Validate with `sniproxy -t -c /etc/sniproxy.conf`, then start in
foreground with `sniproxy -f -c /etc/sniproxy.conf`.

## Usage

```
Usage: sniproxy [-c <config>] [-f] [-g] [-t] [-n <max fd>] [-V] [-T <min TLS>] [-d]
    -c  configuration file (default: /etc/sniproxy.conf)
    -f  run in foreground
    -g  allow group-readable (0640) config for SIGHUP reload
    -t  test configuration and exit
    -n  override file descriptor limit
    -V  print version and exit
    -T  minimum accepted TLS ClientHello version (1.0|1.1|1.2|1.3, default 1.2)
    -d  enable verbose resolver debug tracing
```

## Installation

Every [release](https://github.com/renaudallard/sniproxy/releases)
carries prebuilt packages made by the
[Release Packages](https://github.com/renaudallard/sniproxy/actions/workflows/release-packages.yml)
workflow: x86_64 `.deb` packages for Debian stable and oldstable and
for two Ubuntu releases, x86_64 `.rpm` packages for Fedora, the two
latest Rocky Linux releases, openSUSE Leap and SUSE Linux Enterprise
15, an x86_64 `.apk` for Alpine, a FreeBSD amd64 tarball and a macOS
arm64 tarball.

### Prerequisites

- autoconf 2.71 or later and automake
- libev, libpcre2-8, c-ares, OpenSSL (or LibreSSL) development headers
- On Linux, libseccomp: optional, but without it the build has no
  seccomp sandbox, and configure does not warn about it
- libbsd, only where libc lacks `arc4random` or `strlcpy`, such as
  glibc before 2.38 (OpenBSD, FreeBSD and macOS have both)
- Perl and cURL for the test suite

### From source

```sh
./autogen.sh && ./configure && make check && sudo make install
```

### Debian / Ubuntu

```sh
sudo apt-get install autotools-dev cdbs debhelper dh-autoreconf dpkg-dev \
    gettext libev-dev libpcre2-dev libc-ares-dev libssl-dev libbsd-dev \
    pkg-config fakeroot devscripts
./autogen.sh && dpkg-buildpackage
sudo dpkg -i ../sniproxy_<version>_<arch>.deb
```

### Alpine

```sh
apk add build-base abuild autoconf automake libtool pkgconf \
    libev-dev pcre2-dev c-ares-dev openssl-dev libbsd-dev
./autogen.sh && ./configure && make dist
cp alpine/APKBUILD /tmp/aport/ && cp sniproxy-*.tar.gz /tmp/aport/
cd /tmp/aport && abuild checksum && abuild -r
apk add --allow-untrusted ~/packages/<arch>/sniproxy-<version>.apk
```

### Fedora / RHEL

```sh
sudo yum install autoconf automake curl gettext-devel libev-devel pcre2-devel \
    pkgconfig rpm-build c-ares-devel openssl-devel libbsd-devel
./autogen.sh && ./configure && make dist
rpmbuild --define "_sourcedir `pwd`" -ba redhat/sniproxy.spec
sudo yum install ../sniproxy-<version>.<arch>.rpm
```

### FreeBSD

```sh
pkg install autoconf automake libtool pkgconf libev pcre2 c-ares
./autogen.sh && ./configure LDFLAGS="-L/usr/local/lib" CPPFLAGS="-I/usr/local/include" && make
sudo make install
sudo cp scripts/sniproxy.rc /usr/local/etc/rc.d/sniproxy
sudo sysrc sniproxy_enable=YES
sudo service sniproxy start
```

The logger and resolver always run in Capsicum capability mode. The
main process enters it too unless a listener, fallback or backend is a
Unix domain socket. The binder never does, since it may have to bind
Unix socket paths. `SNIPROXY_DISABLE_CAPSICUM=1` turns it off.

### macOS (best effort)

```sh
brew install libev pcre2 c-ares openssl autoconf automake gettext libtool
brew link --force gettext      # GNU gettext is needed for autogen.sh
./autogen.sh && ./configure && make
```

## Configuration

A config file has a small set of **global** directives followed by one or
more `listener <addr>` and `table <name>` blocks. SIGHUP triggers a
zero-downtime reload. A few settings only change on restart, and the
reload logs a warning when it ignores one: `user`, `group`, `pidfile`,
the `resolver` block, and, for listeners that already exist,
`tcp_fastopen`, `reuseport` and `ipv6_v6only`. SIGUSR1 dumps the live
connection table to a temporary `connections-XXXXXX` file under
`$XDG_RUNTIME_DIR/sniproxy`, `/var/run/sniproxy`, or
`/tmp/sniproxy-<uid>` (tried in that order).

### Global directives

```nginx
user daemon
group daemon
pidfile /var/run/sniproxy.pid

# Let libev batch I/O readiness and timer wakeups (seconds).
# Defaults trade a tiny amount of latency for throughput; set 0 for
# the lowest possible latency.
io_collect_interval      0.0005
timeout_collect_interval 0.005

# Cap total simultaneous connections. 0 (the default) auto-derives
# ~80% of the file descriptor limit.
max_connections 20000

# Per-IP token-bucket rate (TCP + UDP, default 30/s; 0 disables).
per_ip_connection_rate 50

# Per-IP cap on simultaneous connections (default 0, disabled).
per_ip_max_connections 100

# Prefix length used to group native IPv6 clients for every limit keyed on
# the client address, so a client cannot rotate addresses within its
# allocation to evade them. This covers the two per-IP limits above plus
# max_concurrent_queries_per_client and the backend_affinity hash, so
# clients sharing a prefix also share a DNS query budget and a backend.
# Default 64; set to 128 to key on the exact address.
per_ip_ipv6_prefix 64

# Per-side buffer caps. connection_buffer_limit sets both sides; for
# each side the directive that comes last wins. Defaults: 1 MiB each.
connection_buffer_limit 4M
# client_buffer_limit   4M
# server_buffer_limit   8M

# Cap accepted HTTP/1 headers per request (default 100). HTTP/2
# requests have a fixed limit of 100.
http_max_headers 200

# Only connect to backends in these ranges, so a wildcard backend cannot
# be used to reach arbitrary hosts. allow_except does the opposite:
# everything except the listed ranges, e.g. to keep a wildcard backend
# out of internal address space. Unix socket backends match no range.
backend_acl deny_except {
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
}

# Enable TCP Fast Open (Linux 3.7+/4.11+, FreeBSD 12+). On a platform
# built without TFO support, such as OpenBSD, this line is a
# configuration error.
tcp_fastopen on
```

### Resolver block

```nginx
resolver {
    # ipv4_only | ipv6_only | ipv4_first | ipv6_first | default
    mode ipv4_first

    # DNS-over-TLS upstream.
    # IP literals require either a TLS verification hostname after the
    # slash, or an explicit "/insecure" to opt out of verification.
    # The optional third segment pins the minimum TLS version
    # (tls1.2 default, tls1.3 if your OpenSSL supports it).
    nameserver dot://9.9.9.9/dns.quad9.net/tls1.2

    # Or cleartext upstreams. Do not mix them with dot:// entries: c-ares
    # uses all servers as one failover pool, so a cleartext entry lets a
    # failed TLS handshake fall back to unauthenticated DNS.
    # nameserver 8.8.8.8
    # nameserver 2001:4860:4860::8888

    max_concurrent_queries 512
    max_concurrent_queries_per_client 16

    # off | relaxed (default) | strict; this does not validate DNSSEC,
    # see "DNS resolution" below
    dnssec_validation relaxed
}
```

**Security note**: prefer IP literals with an explicit TLS hostname for
DoT servers. A hostname-only entry is looked up in cleartext through the
system resolver when the resolver process starts, which reveals the name
and lets anyone who can tamper with that lookup break name resolution.
The certificate is still checked against the name, so a forged answer
cannot redirect queries to another server:

```nginx
# Recommended
nameserver dot://9.9.9.9/dns.quad9.net

# Less secure: needs cleartext DNS before DoT becomes available
nameserver dot://dns.quad9.net
```

### Listener and table

```nginx
listener [::]:443 {
    protocol tls
    table secure_hosts

    # Multi-process scale-out via SO_REUSEPORT
    reuseport yes

    # Preserve the client source IP on outbound (IP_TRANSPARENT)
    source client

    # Add a debug line with the size and parser result of each request
    # that fails to parse (the contents are not logged)
    bad_requests log

    # Allow listener: every CIDR not listed is blocked
    acl deny_except {
        10.0.0.0/8
        2001:db8::/32
    }

    # Fallback for requests with no hostname, that cannot be parsed, or
    # that match no table entry, sent with a PROXY v1 header. When a
    # matching backend's name fails to resolve, the connection is closed
    # instead.
    fallback 192.0.2.50:443
    fallback proxy_protocol
    # ...or v2:
    # fallback proxy_protocol_v2
}

table secure_hosts {
    # Per-backend PROXY protocol
    secure.example.com  192.0.2.20:443 proxy_protocol
    other.example.com   192.0.2.21:443 proxy_protocol_v2

    # Same client IP reaches the same backend when DNS returns several
    # records for the name. The hash is seeded per process, so the
    # mapping changes on restart and differs between reuseport workers.
    # TCP only. Without it, and for DTLS, a record is picked at random.
    backend_affinity on
    .*\\.cdn\\.example\\.com$ *:443
}
```

All listener `acl` blocks must use the same policy: mixing
`allow_except` and `deny_except` across listeners aborts startup. The
`backend_acl` policy is independent of them. IPv4 and IPv6 networks
can be mixed in the same block; IPv4-mapped IPv6 connections are matched
against the IPv4 CIDRs.

### XMPP

```nginx
listener 0.0.0.0:5222 {
    protocol xmpp
    table xmpp_servers
    fallback 192.0.2.50:5222
}

table xmpp_servers {
    example.com      192.0.2.10:5222
    chat.example.org 192.0.2.11:5222
    .*\\.xmpp\\.net$ *:5222
}
```

The proxy extracts the `to` attribute from the opening `<stream:stream>`
element and routes accordingly. The STARTTLS negotiation that follows is
transparent. Hostnames are validated (alphanumeric, dot, hyphen,
underscore, bracketed IPv6); control characters, path traversal and
injection metacharacters are rejected. Maximum hostname length is 255
bytes, maximum stream header size is 4096 bytes.

### Minecraft

```nginx
listener 0.0.0.0:25565 {
    protocol minecraft
    table minecraft_servers
    fallback 192.0.2.50:25565
}

table minecraft_servers {
    mc.example.com   192.0.2.10:25565
    play.example.org 192.0.2.11:25565
    .*\\.mc\\.net$   *:25565
}
```

The handshake packet is the very first data in the TCP stream, so
sniproxy reads it, cuts the server address at the first NUL byte to
drop any Forge Mod Loader or BungeeCord forwarding trailer, and routes
on what is left. The packet itself reaches the backend unchanged,
trailer included.

## Security and hardening

SNIProxy is built with defense-in-depth as a design goal, not an
afterthought.

- **TLS 1.2+ by default**: older clients can be re-enabled with
  `-T 1.1` or `-T 1.0`, or TLS 1.3 required with `-T 1.3`. The flag
  applies to every TLS listener.
- **Cryptographically random seeds**: the per-IP hashes (rate limiter,
  connection counts, DNS client tracking, backend affinity) are keyed
  with an arc4random seed, and the rate limiter and connection count
  tables refuse clients whose hash chain grows too long, to defeat
  spraying. Request IDs between the main loop and the resolver come from
  arc4random as well.
- **Bounded parsers**: TLS rejects SSL 2.0/3.0 ClientHellos and NUL
  bytes in server names; HTTP caps headers (default 100); TLS extension
  count is capped at 64 on every code path; HTTP/2 HPACK is bounded per
  connection (64 KiB) and globally (4 MiB).
- **Regex DoS mitigation**: PCRE2 match limits scale with hostname
  length so a crafted SNI cannot trigger catastrophic backtracking.
- **DTLS amplification defense**: a new UDP session is held until a
  second datagram arrives from the same source address and port within
  3 seconds, and nothing is sent to the client or a backend before that.
  Real DTLS clients retransmit by design (RFC 6347 section 4.2.4), so a
  single spoofed packet never reaches a backend. The second datagram is
  not compared with the first and no HelloVerifyRequest is sent, so an
  attacker who sends two spoofed packets does get through; from there it
  is the backend's own DTLS cookie exchange that limits amplification.
- **Privilege separation**: the privileged binder, the log writer
  and the resolver are each their own process, communicating over
  encrypted Unix sockets with framed, length-checked messages.
- **Strict config and pidfile checks**: config files must not be
  accessible to group or others (`-g` allows group read only); the
  `pidfile` and log file paths must be absolute; resolver search domains
  are treated as literal suffixes, not re-parsed by the system resolver.
  Pidfiles refuse to be written over stale sockets, FIFOs or symlinks.
- **Privilege drop verification**: startup aborts if real or effective
  UID is still 0 after `setuid()`.
- **OpenBSD sandboxing**: every process runs under pledge(2), and the
  main loop and the logger narrow their promises again once startup is
  done. unveil(2) limits the main loop, and the binder and resolver it
  forks afterwards, to the paths they need; the logger is forked before
  that and has no unveil.
- **FreeBSD sandboxing**: Capsicum capability mode is entered after
  the resolver loads its CA bundle, the logger has its log dirfds
  pre-opened, and the main loop has its config dir + temp dir
  pre-opened for `openat()`. Adding a new log path during SIGHUP reload
  is not supported in capability mode; set `SNIPROXY_DISABLE_CAPSICUM=1`
  for debugging.
- **Linux sandboxing**: seccomp BPF filters per process type, when
  built with libseccomp (configure uses it if it finds it, and the build
  has no seccomp otherwise). `SNIPROXY_DISABLE_SECCOMP=1` turns it off
  for debugging.
- **macOS has no sandbox**: `sandbox_init(3)` and its named profiles
  are deprecated, and a process opting into one is killed outright when
  built against the macOS 27.0 SDK or later, so adopting them would buy a
  hard failure rather than protection. Apple's replacement, App Sandbox,
  is built around entitlements and a per-application container and does
  not fit a daemon that binds a privileged port and writes system logs.
  Everything that does not need kernel support still applies: privilege
  separation, the privilege drop, encrypted IPC and the resource limits.
- **Continuous fuzzing**: protocol fuzzers under `tests/fuzz/` run in
  CI and on a dedicated continuous-fuzzing job. The job only files an
  issue when a real crash/leak/timeout artifact is produced (build
  errors are not treated as false-positive crashes).

Run the regression suite with:

```sh
make check
```

ASan, MSan, UBSan and a combined ASan+UBSan build all run on every push
and pull request via the
[Sanitizers](https://github.com/renaudallard/sniproxy/actions/workflows/sanitizers.yml)
workflow. TSan is available locally through a configure flag (see
[SANITIZERS.md](SANITIZERS.md)).

## DNS resolution

Hostnames in table entries and fallbacks, and the name a client asked
for when it matches a wildcard backend, are resolved by a dedicated
`sniproxy-resolver` child built on [c-ares](https://c-ares.org).
That gives:

- **Process isolation** for DNS code paths
- **Configurable nameservers and search domains** independent of the
  system resolver
- **IPv4/IPv6 preference modes** for mixed-stack deployments
- **Concurrency caps**, globally and per client, to bound resolver memory

sniproxy does not validate DNSSEC itself. `dnssec_validation relaxed`
(the default) and `strict` only turn on EDNS0 in c-ares, and `off`
leaves c-ares at its defaults. Nothing checks the AD flag: `strict`
relies on c-ares flags that do not exist, so it is treated as `relaxed`
and a notice is logged.

For production, run a local validating resolver (Unbound, dnsmasq) and
point sniproxy at it. That is what provides DNSSEC protection, and it
also reduces spoofing exposure and upstream query volume.

## Performance

- **Event-driven I/O** via libev; thousands of concurrent connections per
  process.
- **Per-connection buffers**: each connection starts with a 16 KiB
  client buffer and a 32 KiB server buffer, which grow on demand up to
  the configured caps. Idle buffers shrink back, the client one down to
  8 KiB and the server one to its initial 32 KiB.
- **Memory-pressure trimming**: a global soft limit drives an
  aggressive shrink pass against idle buffers before total RAM balloons;
  the shrink candidate queue is itself bounded (4096 entries).
- **TCP_NODELAY** on both sides to avoid Nagle coalescing delays.
- **SO_SPLICE zero-copy on OpenBSD**: once the handshake is parsed the
  kernel splices client and server sockets directly; user-space buffers
  shrink to 4 KiB and the idle timer polls the kernel byte counters of
  both directions before closing a quiet connection.
- **JIT regex**: PCRE2 JIT compilation is used where available.
- **HPACK ring buffer**: HTTP/2 dynamic table inserts are O(1).
- **SO_REUSEPORT**: run several sniproxy instances on the same port;
  on Linux 3.9+ the kernel spreads new connections across them.
- **Hot reload**: SIGHUP updates routing tables in place; connections
  that are already routed keep their backend.

## Troubleshooting

**"Address already in use" on start**

A previous instance or another service is bound to the listener address.
Inspect with `ss -tlnp` or `netstat -tlnp`. For multi-worker setups, set
`reuseport yes` on the listener.

**Connections are not routed (or hit the fallback)**

- Confirm the listener references the right `table <name>`.
- Verify the pattern is a valid regex when it contains metacharacters
  (`.*\\.example\\.com$`, not `*.example.com`). The config parser
  consumes one backslash, so a backslash meant for the regex must be
  doubled; `sniproxy -t` prints each pattern as it will be compiled.
  Bare hostnames are auto-anchored, regexes are not.
- Check the error log: a request without a hostname or one that fails
  to parse is logged as a warning, with the client address.

**DNS is not working**

- Check that the resolver process is alive: `pgrep -l sniproxy` lists
  every sniproxy process by name. Linux truncates names to 15
  characters, so it shows up there as `sniproxy-resolv`.
- Run in the foreground with `-d` (see Debug mode below) to trace each
  lookup.
- Verify the `resolver { nameserver ... }` config and network
  reachability.

**Memory keeps climbing**

- Look for connections stuck in DNS resolution with a flaky upstream;
  lower `max_concurrent_queries` and `max_concurrent_queries_per_client`.
- Lower `connection_buffer_limit` or the per-side caps.

**Permission errors on start**

- The configured `user`/`group` must exist.
- Log files are created at startup, before privileges are dropped, and
  handed over to that user. If logs are rotated by renaming them, the
  log directory must be writable by that user so SIGHUP can create the
  new file.
- On OpenBSD, the directories holding the log files and the pidfile
  must already exist before launch, because unveil cannot reveal what is
  not there. The files themselves may be missing.

**HTTP/2 connection coalescing routes to the wrong backend**

HTTP/2 clients (browsers) will reuse a single TLS connection for any
second hostname when (1) the two names resolve to the same IP and (2)
the server certificate is valid for both (typical wildcard cert
`*.example.com`). Since every name proxied by sniproxy resolves to the
sniproxy IP, condition (1) is always satisfied. If the backend serves a
shared cert, the browser will multiplex requests for different names
over one connection, and sniproxy routes once per TCP connection from
the SNI and cannot see the encrypted HTTP/2 frames, so subsequent
requests are sent to the wrong backend.

Symptoms: 404s, CORS failures, "Access denied" responses, or content
from the wrong site. Restarting the browser clears it temporarily.

Workarounds (in order of cleanness):

1. **Per-domain certificates** on the backends instead of wildcards
   (Let's Encrypt makes this trivial). This is the most effective fix.
2. **Backends return HTTP 421 (Misdirected Request)** for hostnames they
   do not serve. RFC 9110 says compliant browsers must retry on a fresh
   connection.
3. **Separate IPs per backend** so the browser's IP-match check fails
   (IPv6 makes this easy).
4. **Disable HTTP/2 on backends** by stripping `h2` from ALPN. Loses
   HTTP/2 performance but eliminates coalescing.

For third-party services where you control neither the cert nor the
backend (CDNs, hosted SaaS), there is no in-proxy workaround; use a
TLS-terminating reverse proxy for those names.

### Debug mode

```sh
sniproxy -f -d -c /etc/sniproxy.conf
```

`-f` keeps the process in the foreground; `-d` turns on verbose resolver
tracing. The resolver process writes it to stderr or to syslog: it cannot
write to a file error log owned by the main process, so with `error_log {
filename ... }` its messages go to syslog with the daemon facility.

## How it compares

All five of these can route a connection by the name the client asked
for without decrypting it. They differ in what else they are, and in
what they bring to that job.

| | sniproxy (this fork) | sniproxy (upstream) | HAProxy | nginx `stream` | Envoy |
| --- | --- | --- | --- | --- | --- |
| Routes by name, no decryption | yes | yes | yes (`req.ssl_sni`, `mode tcp`) | yes (`ssl_preread`) | yes (TLS inspector) |
| Protocols routed by name | TLS, HTTP/1, HTTP/2, XMPP, Minecraft, DTLS | TLS, HTTP | TLS, HTTP | TLS (SNI, ALPN) | TLS, HTTP |
| Name-based UDP / DTLS | yes, with a source address check | no | no | no, `ssl_preread` is TCP only | no, sessions are keyed on the 4-tuple |
| Process model | 4 processes, separate privileges | single process | master + workers | master + workers | single process, threaded |
| Sandbox shipped with it | pledge/unveil, Capsicum, seccomp | none | chroot, privilege drop | privilege drop (`user`) | left to the deployment |
| Encrypted IPC between its own processes | ChaCha20-Poly1305 | n/a | n/a | n/a | n/a |
| What else it is | an SNI router | an SNI router | a full L4/L7 load balancer | a web server and L4 proxy | a full service proxy |

The table covers the name-routing path only. HAProxy, nginx and Envoy
are general-purpose proxies with far larger feature sets, and on a host
where you already run one of them, adding sniproxy buys you little. It
earns its own process when you want name-based routing on its own, with
a small attack surface, on a machine that terminates no TLS at all.

Third-party cells come from each project's own documentation:
[ssl_preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html),
[HAProxy configuration manual](https://docs.haproxy.org/3.0/configuration.html),
[Envoy TLS inspector](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/tls_inspector),
[Envoy UDP proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/udp_filters/udp_proxy),
[upstream sniproxy](https://github.com/dlundquist/sniproxy).

## Project status

SNIProxy is actively maintained with a focus on security, stability and
standards compliance. Recent releases have concentrated on protocol
parser hardening, sandboxing portability and continuous fuzzing.

Common deployments:

- Name-based HTTPS virtual hosting without TLS termination
- TLS / SSL load balancing by SNI across backend pools
- Multi-tenant hosting (multiple domains, distinct backend
  infrastructure, single public IP)
- CDN origin selection by hostname
- XMPP federation routing with STARTTLS passthrough
- Multi-server Minecraft Java Edition hosting behind one IP and port
- DTLS / UDP routing for WebRTC, OpenConnect VPN, CoAP and other
  UDP/DTLS protocols, by hostname, without decryption
- Local development HTTPS routing
- Lightweight SNI routing on IoT and embedded systems

## Contributing

Contributions are welcome. Areas of particular interest:

- Additional protocol parsers
- Performance work
- Additional fuzz harnesses or sanitizer coverage
- Documentation
- Bug reports with reproducers

Please build with the sanitizers and run `make check` locally before
opening a pull request. ASan and UBSan run automatically on every PR.

## Resources

- **Source**: https://github.com/renaudallard/sniproxy
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Sanitizers**: [SANITIZERS.md](SANITIZERS.md)
- **Issues**: GitHub Issues
- **License**: BSD 2-Clause, see [COPYING](COPYING)
- **Donate**: [PayPal](https://www.paypal.me/RenaudAllard)

## Credits

Current maintainer: **Renaud Allard** &lt;renaud@allard.it&gt;

Original author: **Dustin Lundquist** &lt;dustin@null-ptr.net&gt;

Contributors: Chris Lundquist, Igor Novgorodov, Nikos Mavrogiannopoulos,
Vit Herman, Remi Gacogne, Pieter Lexis, Oldrich Jedlicka, Nick Kugaevsky,
Manuel Kasper, Lars Reemts, Bearnard Hibbins, Robin Balyan, Andrej Manduch,
Andreas Loibl, Aaron Schrab, Zhang Sen, Udit Raikwar, Thomas Nordquist,
Theophile Helleboid, Sebastian Wiedenroth, RickieL, Pierre-Olivier Mercier,
Peter van Dijk, Naveen Nathan, Marc Haber, Kirill Ponomarev, John Wang,
imlonghao, Christopher Galtenberg, Bram Gotink, Arni Birgisson.

Built on:

- [libev](http://software.schmorp.de/pkg/libev.html): event loop
- [PCRE2](https://www.pcre.org/): regular expressions
- [c-ares](https://c-ares.org): asynchronous DNS

All production testing is performed on OpenBSD. Patches and bug reports
for other platforms are welcome.
