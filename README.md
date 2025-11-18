SNI Proxy
=========

Proxies incoming HTTP and TLS connections based on the hostname contained in
the initial request of the TCP session. This enables HTTPS name-based virtual
hosting to separate backend servers without installing the private key on the
proxy machine.

SNIProxy is a production-ready, high-performance transparent proxy with a focus
on security, reliability, and minimal resource usage.

Features
--------

### Core Functionality
+ **Name-based proxying** of HTTPS without decrypting traffic - no keys or
  certificates required on the proxy
+ **Protocol support**: TLS (SNI extraction), HTTP/1.x (Host header), and
  HTTP/2 (HPACK :authority pseudo-header)
+ **Pattern matching**: Exact hostname matching and PCRE2 regular expressions
+ **Wildcard backends**: Route to dynamically resolved hostnames
+ **Fallback routing**: Default backend for requests without valid hostnames
+ **HAProxy PROXY protocol**: Propagate original client IP/port to backends (v1/v2)

### Network & Performance
+ **IPv4, IPv6, and Unix domain sockets** for both listeners and backends
+ **Multiple listeners** per instance with independent configurations
+ **Source address binding** for outbound connections
+ **Transparent proxy mode** (IP_TRANSPARENT) to preserve client source IPs
+ **SO_REUSEPORT** support for multi-process scalability
+ **Event-driven architecture** using libev for efficient I/O multiplexing
+ **Dynamic ring buffers** with automatic growth/shrinking
+ **Memory pressure trimming**: global soft limit aggressively shrinks idle connection buffers before RAM balloons
+ **Per-connection buffer caps**: configurable `connection_buffer_limit` (or per-side overrides) prevent slow clients from pinning unbounded RAM
+ **Zero-copy operations** where supported (splice on Linux)
+ **Bounded shrink queues**: 4096-entry shrink candidate lists with automatic
  trimming prevent idle buffer bookkeeping from exhausting memory under churn.

### Security & Hardening
+ **TLS 1.2+ required by default** - use `-T <version>` to allow older TLS 1.1/1.0 clients or enforce TLS 1.3 for stricter deployments
+ **Cryptographic DNS query IDs**: arc4random()-seeded IDs with lifecycle
  tracking prevent prediction or reuse
+ **Regex DoS prevention**: Match limits scale with hostname length
+ **Buffer overflow protection**: Strict bounds checking in all protocol parsers
+ **NULL byte rejection**: Prevents hostname validation bypasses
+ **Listener ACLs**: CIDR-based allow/deny policies per listener to block or permit client ranges
+ **HTTP/2 memory limits**: Per-connection and global HPACK table size caps
+ **Request guardrails**: Caps of 100 HTTP headers and 64 TLS extensions stop
  CPU exhaustion attempts before parsers process attacker-controlled blobs.
+ **Rate limiter collision defense**: arc4random()-seeded buckets use FNV-1a
  hashing and short-chain cutoffs so hash spraying cannot bypass per-IP token
  buckets.
+ **DNS resolver hardening**: Async-signal-safe handlers, integer overflow
  protection, arc4random()-seeded query IDs, mutex-guarded restart state, and
  leak-resistant handle accounting prevent prediction, leaks, or use-after-free
  bugs.
+ **DNS query concurrency limits**: Prevents resolver exhaustion
+ **Connection idle timeouts**: Automatic cleanup of stalled connections
+ **Per-IP connection rate limiting**: Token-bucket guardrail on new client connections across all listeners
+ **Privilege separation**: Separate processes for logging and DNS resolution
+ **OpenBSD sandboxing**: pledge(2) and unveil(2) for minimal system access
+ **Input sanitization**: Hostname validation, control character removal
+ **Comprehensive fuzzing**: TLS and HTTP/2 protocol fuzzers included

### DNS Resolution
+ **Asynchronous DNS** via dedicated resolver process (powered by c-ares from 0.8.7)
+ **IPv4/IPv6 preference modes**: default, IPv4-only, IPv6-only, IPv4-first, IPv6-first
+ **Configurable nameservers** and search domains
+ **Concurrency limits** to prevent resource exhaustion

### Operations & Management
+ **Hot configuration reload** via SIGHUP without dropping connections
+ **Reference counting** ensures safe updates during reload
+ **Flexible logging**: Syslog and file-based logs with per-listener overrides
+ **Access logs** with connection duration and byte transfer statistics
+ **Process renaming**: Processes show as `sniproxy-mainloop` (Linux only),
  `sniproxy-binder`, `sniproxy-logger`, and `sniproxy-resolver` in process listings
+ **IPC hardening**: binder/logger/resolver channels encrypt control messages,
  validate framing, enforce `max_payload_len`, and emit clear restart guidance
+ **PID file support** for process management with strict validation that
  rejects stale sockets, FIFOs, or symlinks before writing
+ **Privilege dropping** to non-root user/group after binding privileged ports
+ **Privilege verification**: startup fails fast if real or effective UID remains root after dropping privileges
+ **Config permission guard**: sniproxy and sniproxy-cfg refuse to run when the configuration file is accessible to group/other users
+ **Legacy config compatibility**: Accepts older `listen`, `proto`, `user`, `group`
  keywords
+ **Resolver debug tracing**: Enable verbose DNS resolver logs on demand with the
  `-d` CLI flag for troubleshooting query flow

Architecture
------------

SNIProxy uses a multi-process architecture for security and isolation:

1. **Main process** (`sniproxy-mainloop`): Accepts connections, parses protocol headers, routes to
   backends, and proxies data bidirectionally
2. **Binder process** (`sniproxy-binder`): Creates privileged listening sockets before
   and after reloads so the main loop can drop root while still opening low ports
3. **Logger process** (`sniproxy-logger`): Handles all log writes with dropped
   privileges, enabling secure logging from the main process
4. **Resolver process** (`sniproxy-resolver`): Performs asynchronous DNS lookups
   in isolation when DNS support is enabled

This separation ensures that even if a component is compromised, the attack
surface is minimized. The main process drops privileges after binding to ports,
and helper processes run with minimal system access.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

Usage
-----

    Usage: sniproxy [-c <config>] [-f] [-n <max file descriptor limit>] [-V] [-T <min TLS version>] [-d]
        -c  configuration file, defaults to /etc/sniproxy.conf
        -f  run in foreground, do not drop privileges
        -n  specify file descriptor limit
        -V  print the version of SNIProxy and exit
        -T  <1.0|1.1|1.2|1.3> set minimum TLS client hello version (default 1.2)
        -d  enable resolver debug logging (verbose DNS tracing to stderr/error log)


Installation
------------

For Debian or Fedora based Linux distributions see building packages below.

**Prerequisites**

+ Autotools (autoconf, automake, gettext and libtool)
+ libev4, libpcre2 and c-ares development headers
+ Perl and cURL for test suite

**Install**

    ./autogen.sh && ./configure && make check && sudo make install

**Building Debian/Ubuntu package**

This is the preferred installation method on recent Debian based distributions:

1. Install required packages

        sudo apt-get install autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre2-dev libc-ares-dev pkg-config fakeroot devscripts

2. Build a Debian package

        ./autogen.sh && dpkg-buildpackage

3. Install the resulting package

        sudo dpkg -i ../sniproxy_<version>_<arch>.deb

**Building Fedora/RedHat package**

This is the preferred installation method for modern Fedora based distributions.

1. Install required packages

        sudo yum install autoconf automake curl gettext-devel libev-devel pcre2-devel perl pkgconfig rpm-build c-ares-devel

2. Build a distribution tarball:

        ./autogen.sh && ./configure && make dist

3. Build a RPM package

        rpmbuild --define "_sourcedir `pwd`" -ba redhat/sniproxy.spec

4. Install resulting RPM

        sudo yum install ../sniproxy-<version>.<arch>.rpm

I've used Scientific Linux 6 a fair amount, but I prefer Debian based
distributions. RPM builds are tested in Travis-CI on Ubuntu, but not natively.
This build process may not follow the current Fedora packaging standards, and
may not even work.

***Building on OS X with Homebrew***

1. install dependencies.

        brew install libev pcre2 c-ares autoconf automake gettext libtool

2. Read the warning about gettext and force link it so autogen.sh works. We need the GNU gettext for the macro `AC_LIB_HAVE_LINKFLAGS` which isn't present in the default OS X package.

        brew link --force gettext

3. Make it so

        ./autogen.sh && ./configure && make

OS X support is a best effort, and isn't a primary target platform.


Configuration Syntax
--------------------

Global directives appear before any `listener` or `table` blocks. In addition to
standard items such as `user`, `group`, `pidfile`, `resolver`, and `access_log`,
you can keep abusive clients in check with a global per-IP rate limiter:

```
per_ip_connection_rate 50   # allow 50 new connections per second per source IP
```

The default is 30 connections per second. Set the value to `0` to disable the
limiter entirely.

To guard against descriptor exhaustion during floods, cap the number of
concurrent connections (set `0` to auto-derive ~80% of the file descriptor
limit, which is the default):

```
max_connections 20000
```

To cap how much memory any one connection can pin, set a shared limit (or
override each side independently):

```
connection_buffer_limit 4M     # both client and server buffers cap at 4 MiB
# client_buffer_limit 4M       # optional per-side overrides
# server_buffer_limit 8M
```

### Basic Configuration

    user daemon
    group daemon

    pidfile /tmp/sniproxy.pid

    # Allow libev to batch events for better throughput (seconds)
    io_collect_interval 0.0005
    timeout_collect_interval 0.005

    error_log {
        filename /var/log/sniproxy/error.log
        priority notice
    }

    listener 127.0.0.1:443 {
        protocol tls
        table TableName

        # Specify a server to use if the initial client request doesn't contain
        # a hostname
        fallback 192.0.2.5:443

        # Optional: bind outbound connections to specific source address
        source 192.0.2.100

        # Optional: per-listener access log
        access_log {
            filename /var/log/sniproxy/access.log
        }
    }

    table TableName {
        # Match exact request hostnames
        example.com 192.0.2.10:4343

        # If port is not specified the listener port will be used
        example.net [2001:DB8::1:10]

        # Use regular expressions to match multiple hosts
        .*\\.example\\.com    192.0.2.11:443

        # Wildcard backends resolve the client-requested hostname
        .*\\.dynamiccdn\\.com    *:443
    }

### Advanced Configuration

    resolver {
        # DNS resolution mode: ipv4_only, ipv6_only, ipv4_first, ipv6_first
        mode ipv4_first

        # Custom nameservers (handled by c-ares)
        nameserver 8.8.8.8
        nameserver 2001:4860:4860::8888
        # DNS-over-TLS upstream with explicit TLS verification hostname
        #nameserver dot://9.9.9.9/dns.quad9.net

        # Limit concurrent DNS queries to prevent resource exhaustion
        max_concurrent_queries 256

        # DNSSEC policy (default relaxed): off | relaxed | strict
        dnssec_validation strict
    }

    listener [::]:443 {
        protocol tls
        table SecureHosts

        # Enable SO_REUSEPORT for multi-process load balancing
        reuseport yes

        # Enable IP_TRANSPARENT to preserve client source IPs
        source client

        # Log malformed/rejected requests
        bad_requests log

        # Restrict which clients may connect (default is allow all)
        acl deny_except {
            10.0.0.0/8
            2001:db8::/32
        }


        # Fallback with PROXY protocol header
        fallback 192.0.2.50:443
        fallback proxy
    }

    table SecureHosts {
        # Enable PROXY protocol for all backends in this table
        use_proxy_header yes

        # Backend-specific PROXY protocol override
        secure.example.com 192.0.2.20:443 { use_proxy_header no }
    }

Setting `io_collect_interval` and `timeout_collect_interval` lets libev batch I/O readiness notifications and timer recalculations, which reduces system call pressure on busy instances. The defaults (0.0005s and 0.005s respectively) favor throughput; set the values to 0 if you need the absolute lowest latency.

Listeners default to accepting clients from any address. Use `acl allow_except` to list forbidden ranges while permitting all other clients, or `acl deny_except` to start from a deny-all stance and explicitly list the ranges that should be accepted. IPv4 and IPv6 networks can be mixed in the same block, and IPv4-mapped IPv6 connections are evaluated against IPv4 CIDRs. Only one policy style may appear in the configuration; mixing `allow_except` and `deny_except` blocks causes SNIProxy to exit during parsing.


DNS Resolution
--------------

Using hostnames or wildcard entries in the configuration relies on [c-ares](https://c-ares.org) for asynchronous resolution. DNS-dependent features such as fallback hostnames, wildcard tables, and transparent proxy mode all use this resolver.

SNIProxy spawns a dedicated `sniproxy-resolver` process that handles all DNS queries asynchronously. This architecture provides:

- **Process isolation**: DNS operations are separated from the main proxy
- **Concurrency control**: Configurable limits prevent resolver exhaustion
- **IPv4/IPv6 flexibility**: Multiple resolution modes for different deployment needs
- **Custom nameservers**: Override system DNS configuration per SNIProxy instance

**Security note**: Run SNIProxy alongside a local caching DNS resolver (e.g., unbound, dnsmasq) to reduce exposure to spoofed responses and improve performance.

DNSSEC validation runs in `relaxed` mode by default, which requests DNSSEC records and trusts replies carrying the AD flag while still falling back to unsigned answers when AD isn't set. Set `dnssec_validation strict` inside the `resolver` block to require DNS replies that carry the AD (Authenticated Data) flag from a validating upstream resolver. This mode needs a c-ares build with DNSSEC/Trust AD support and will fail to resolve unsigned zones. Use `dnssec_validation off` to disable DNSSEC entirely if your upstream resolvers do not support it.


Security & Hardening
--------------------

SNIProxy includes extensive security hardening:

### Security Controls

- **DNS query ID randomization**: Uses a xorshift32 PRNG instead of a linear counter to prevent timing-based prediction attacks
- **c-ares resolver hardening**: Async-signal-safe signal handlers, integer overflow protection, and leak fixes keep the resolver stable under load
- **TLS parser hardening**: Early rejection of SSL 2.0/3.0 and malformed ClientHello variants that cannot carry the SNI extension
- **Regex DoS mitigation**: Match limits scale with hostname length to prevent catastrophic backtracking on hostile hostnames
- **Buffer overflow protection**: `buffer_reserve()` enforces strict overflow guards to block integer wraparound attempts
- **NUL byte filtering**: TLS SNI parsing rejects server names with embedded NUL bytes before hostname validation
- **HTTP/2 memory limits**: Enforces per-connection (64KB) and global (4MB) HPACK table limits to avoid memory exhaustion
- **PROXY header hardening**: Single-pass header composition eliminates read-past-buffer bugs
- **Connection timeout protection**: Idle timers clear pending events to prevent use-after-free conditions
- **DNS concurrency limits**: Mutex-protected resolver queues enforce configurable caps on in-flight lookups

### Testing Infrastructure

The project includes comprehensive testing:

- **Unit tests**: All major components (buffer, TLS, HTTP, HTTP/2, tables, etc.)
- **Fuzz testing**: Dedicated fuzzers for TLS ClientHello and HTTP/2 HEADERS
  parsing in `tests/fuzz/`
- **Integration tests**: End-to-end listener and routing validation
- **Protocol conformance**: Tests for TLS 1.0-1.3, HTTP/1.x, and HTTP/2

Run tests with: `make check`

### OpenBSD Sandboxing

On OpenBSD, SNIProxy combines unveil(2) and pledge(2) to keep each helper process constrained:

- **unveil()**: Restricts access to the configuration file, pidfile, log destinations, and Unix domain sockets declared in the configuration
- **pledge()**: Promise sets are tailored per process to minimize available system calls:
  - Main process: starts with `stdio getpw inet dns rpath proc id wpath cpath unix` while reading configuration, then tightens to `stdio inet dns rpath proc id unix` after dropping privileges
  - Binder process: `stdio unix inet` while handling privileged socket creation
  - Logger process: `stdio rpath wpath cpath fattr id unix` so it can rotate and chown log files but cannot reach the network
  - Resolver process: `stdio inet dns unix` to perform DNS lookups in isolation

All paths are collected from the loaded configuration, so custom locations work
as long as files/directories exist before launch. After unveiling resources,
SNIProxy pledges minimal runtime promises and a restricted exec profile for
spawning helper processes.

Performance Notes
-----------------

SNIProxy is designed for high performance and low resource usage:

- **Event-driven I/O**: Uses libev for efficient non-blocking I/O multiplexing,
  handling thousands of concurrent connections per process
- **Minimal per-connection overhead**: Dynamic buffers start small and grow only
  as needed, then shrink when idle
- **Zero-copy operations**: Uses splice() on Linux to move data between sockets
  without copying through userspace
- **SO_REUSEPORT support**: Run multiple SNIProxy instances on the same port for
  kernel-level load balancing across CPU cores
- **Compiled regex patterns**: Pattern matching happens once at config load,
  not per connection
- **Hot config reload**: Update routing rules without restarting or dropping
  existing connections (SIGHUP)

**Typical resource usage**: 1-2 MB RAM per process plus ~2-8 KB per active
connection (varies with traffic patterns)

Troubleshooting
---------------

### Common Issues

**"Address already in use" when starting**
- Another process is bound to the port, or a previous SNIProxy instance didn't
  clean up. Use `netstat -tlnp` or `ss -tlnp` to check.
- Try enabling `reuseport yes` in listener config for multi-instance setups

**Connections fail to route / "No matching backend"**
- Check that table names match between listener and table definitions
- Verify hostname patterns - remember that regex patterns need proper escaping
  (e.g., `.*\.example\.com` not `*.example.com`)
- Enable `bad_requests log` to see rejected requests in error log

**DNS resolution not working**
- Ensure the c-ares development headers were available when SNIProxy was built
- Check `sniproxy-resolver` process is running (should appear in process list)
- Verify nameserver configuration and network connectivity

**High memory usage**
- Check for connections stuck in RESOLVING state with slow/unresponsive DNS
- Reduce `max_concurrent_queries` to limit DNS-related memory
- Verify no regex patterns causing excessive backtracking (check error log)

**Permissions errors on startup**
- Ensure user/group specified in config exists
- Verify log file directories are writable by the configured user
- On OpenBSD, ensure all paths exist before starting (for unveil)

### Debug Mode

Run in foreground with resolver debug logging enabled:

    sniproxy -f -d -c /path/to/config.conf

This will:
- Keep process in foreground (not daemonize)
- Not drop privileges (runs as invoking user)
- Show detailed resolver tracing on stderr/error log to troubleshoot DNS issues

### Configuration Testing

Validate configuration syntax:

    sniproxy-cfg -c /path/to/config.conf

Use `-p` to dump the normalized configuration when you need to inspect the
resolved listener/table definitions.

Project Status
--------------

SNIProxy is actively maintained with a focus on security, stability, and
standards compliance. The codebase has undergone extensive security hardening
in recent releases, including protection against regex DoS, buffer overflows,
and memory exhaustion attacks.

**Primary platform**: OpenBSD
**Best-effort support**: Linux, Other BSDs, macOS

### Use Cases

SNIProxy is production-ready and commonly used for:

- **Name-based virtual hosting**: Route HTTPS traffic by hostname without
  TLS termination
- **TLS/SSL load balancing**: Distribute connections across backend servers
  based on SNI
- **Multi-tenant hosting**: Route multiple domains to different backend
  infrastructure
- **CDN origins**: Route traffic to appropriate origin servers by hostname
- **Development proxies**: Local HTTPS routing for development environments
- **IoT/embedded systems**: Lightweight SNI routing with minimal resource usage

### Contributing

Contributions are welcome! Areas of particular interest:

- Additional protocol parsers (QUIC, etc.)
- Performance optimizations
- Security improvements
- Documentation improvements
- Bug reports and test cases

### Resources

- **Source code**: https://github.com/renaudallard/sniproxy
- **Architecture documentation**: See [ARCHITECTURE.md](ARCHITECTURE.md)
- **Issue tracking**: GitHub Issues
- **License**: BSD 2-Clause

### Credits

Current author: Renaud Allard <renaud@allard.it>

Thanks to the original author: Dustin Lundquist <dustin@null-ptr.net>

Contributors: Manuel Kasper and others

### Nota Bene

All real life tests are only done on OpenBSD. If you see issues on other OSes
feel free to submit PRs or bug reports.

SNIProxy builds on several excellent libraries:
- [libev](http://software.schmorp.de/pkg/libev.html) - event loop
- [PCRE2](https://www.pcre.org/) - regex
- [c-ares](https://c-ares.org) - async DNS resolution
