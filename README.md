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
+ **Pattern matching**: Exact hostname matching and PCRE/PCRE2 regular expressions
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
+ **Zero-copy operations** where supported (splice on Linux)

### Security & Hardening
+ **TLS 1.2+ required by default** - optionally allow TLS 1.0 with `-T` flag
+ **Regex DoS prevention**: Match limits scale with hostname length
+ **Buffer overflow protection**: Strict bounds checking in all protocol parsers
+ **NULL byte rejection**: Prevents hostname validation bypasses
+ **HTTP/2 memory limits**: Per-connection and global HPACK table size caps
+ **DNS query concurrency limits**: Prevents resolver exhaustion
+ **Connection idle timeouts**: Automatic cleanup of stalled connections
+ **Per-IP connection rate limiting**: Token-bucket guardrail on new client connections across all listeners
+ **Privilege separation**: Separate processes for logging and DNS resolution
+ **OpenBSD sandboxing**: pledge(2) and unveil(2) for minimal system access
+ **Input sanitization**: Hostname validation, control character removal
+ **Comprehensive fuzzing**: TLS and HTTP/2 protocol fuzzers included

### DNS Resolution
+ **Asynchronous DNS** via dedicated resolver process (powered by c-ares)
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
+ **PID file support** for process management
+ **Privilege dropping** to non-root user/group after binding privileged ports
+ **Legacy config compatibility**: Accepts older `listen`, `proto`, `user`, `group`
  keywords

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

    Usage: sniproxy [-c <config>] [-f] [-n <max file descriptor limit>] [-V] [-T]
        -c  configuration file, defaults to /etc/sniproxy.conf
        -f  run in foreground, do not drop privileges
        -n  specify file descriptor limit
        -V  print the version of SNIProxy and exit
        -T  allow TLS 1.0 client hellos (default requires TLS 1.2+)


Installation
------------

For Debian or Fedora based Linux distributions see building packages below.

**Prerequisites**

+ Autotools (autoconf, automake, gettext and libtool)
+ libev4, libpcre2 (or libpcre) and c-ares development headers
+ Perl and cURL for test suite

**Install**

    ./autogen.sh && ./configure && make check && sudo make install

**Building Debian/Ubuntu package**

This is the preferred installation method on recent Debian based distributions:

1. Install required packages

        sudo apt-get install autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre2-dev libcares-dev pkg-config fakeroot devscripts

2. Build a Debian package

        ./autogen.sh && dpkg-buildpackage

3. Install the resulting package

        sudo dpkg -i ../sniproxy_<version>_<arch>.deb

**Building Fedora/RedHat package**

This is the preferred installation method for modern Fedora based distributions.

1. Install required packages

        sudo yum install autoconf automake curl gettext-devel libev-devel pcre-devel perl pkgconfig rpm-build c-ares-devel

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

        brew install libev pcre c-ares autoconf automake gettext libtool

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

Set the value to `0` to disable the limiter (default).

### Basic Configuration

    user daemon
    group daemon

    pidfile /tmp/sniproxy.pid

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

        # Limit concurrent DNS queries to prevent resource exhaustion
        max_concurrent_queries 256

        # Require DNS answers validated via DNSSEC by the upstream resolver
        dnssec_validation on
    }

    listener [::]:443 {
        protocol tls
        table SecureHosts

        # Enable SO_REUSEPORT for multi-process load balancing
        reuseport yes

        # Enable IP_TRANSPARENT to preserve client source IPs
        transparent_proxy yes

        # Log malformed/rejected requests
        bad_requests log

        # Fallback with PROXY protocol header
        fallback 192.0.2.50:443
        fallback_use_proxy_header yes
    }

    table SecureHosts {
        # Enable PROXY protocol for all backends in this table
        use_proxy_header yes

        # Backend-specific PROXY protocol override
        secure.example.com 192.0.2.20:443 { use_proxy_header no }
    }

DNS Resolution
--------------

Using hostnames or wildcard entries in the configuration relies on [c-ares](https://c-ares.org) for asynchronous resolution. DNS-dependent features such as fallback hostnames, wildcard tables, and transparent proxy mode all use this resolver.

SNIProxy spawns a dedicated `sniproxy-resolver` process that handles all DNS queries asynchronously. This architecture provides:

- **Process isolation**: DNS operations are separated from the main proxy
- **Concurrency control**: Configurable limits prevent resolver exhaustion
- **IPv4/IPv6 flexibility**: Multiple resolution modes for different deployment needs
- **Custom nameservers**: Override system DNS configuration per SNIProxy instance

**Security note**: Run SNIProxy alongside a local caching DNS resolver (e.g., unbound, dnsmasq) to reduce exposure to spoofed responses and improve performance.

Enabling `dnssec_validation on` inside the `resolver` block forces SNIProxy to only use DNS answers that your upstream resolver has validated with DNSSEC. This requires a version of c-ares built with DNSSEC/Trust AD support; when unavailable, SNIProxy will refuse to start rather than silently disable the protection.


Security & Hardening
--------------------

SNIProxy includes extensive security hardening:

### Recent Security Improvements

- **Regex DoS mitigation**: Match limits now scale with hostname length to
  prevent catastrophic backtracking attacks on malicious hostnames
- **Buffer overflow protection**: Added strict overflow guards in `buffer_reserve()`
  to detect and prevent integer wraparound attacks
- **NUL byte filtering**: TLS SNI parsing rejects server names with embedded NUL
  bytes before hostname validation, preventing filter bypass
- **HTTP/2 memory limits**: Enforced per-connection (64KB) and global (4MB) HPACK
  dynamic table size limits to prevent memory exhaustion
- **PROXY header hardening**: Truncated snprintf results can no longer trick
  buffer operations into reading past temporary buffers
- **Connection timeout protection**: Idle timers now properly clear pending events
  to prevent use-after-free conditions
- **DNS concurrency limits**: Configurable limits with mutex protection around
  the global resolver query list

### Testing Infrastructure

The project includes comprehensive testing:

- **Unit tests**: All major components (buffer, TLS, HTTP, HTTP/2, tables, etc.)
- **Fuzz testing**: Dedicated fuzzers for TLS ClientHello and HTTP/2 HEADERS
  parsing in `tests/fuzz/`
- **Integration tests**: End-to-end listener and routing validation
- **Protocol conformance**: Tests for TLS 1.0-1.3, HTTP/1.x, and HTTP/2

Run tests with: `make check`

### OpenBSD Sandboxing

On OpenBSD, SNIProxy uses pledge(2) and unveil(2) for system call and filesystem
restrictions:

- **unveil()**: Restricts access to configuration file, pidfile, log files, and
  Unix domain sockets referenced in the configuration
- **pledge()**: Reduces available system calls to minimum required set:
  - Main process: `stdio rpath inet dns proc exec`
  - Logger process: `stdio rpath wpath cpath fattr`
  - Resolver process: `stdio inet dns`

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

Run in foreground with debug logging:

    sniproxy -f -c /path/to/config.conf

This will:
- Keep process in foreground (not daemonize)
- Not drop privileges (runs as invoking user)
- Show detailed logging to stderr

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

**Primary platforms**: Linux and OpenBSD
**Best-effort support**: Other BSDs, macOS

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
- Platform support (Windows, other operating systems)
- Documentation improvements
- Bug reports and test cases

### Resources

- **Source code**: https://github.com/renaudallard/sniproxy
- **Architecture documentation**: See [ARCHITECTURE.md](ARCHITECTURE.md)
- **Issue tracking**: GitHub Issues
- **License**: BSD 2-Clause

### Credits

Thanks to the original author: Dustin Lundquist <dustin@null-ptr.net>
Current author: Renaud Allard <renaud@allard.it>

Contributors: Manuel Kasper and others

SNIProxy builds on several excellent libraries:
- [libev](http://software.schmorp.de/pkg/libev.html) - event loop
- [PCRE2](https://www.pcre.org/) / [PCRE](https://www.pcre.org/) - regex
- [c-ares](https://c-ares.org) - async DNS resolution
