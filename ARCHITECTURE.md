# SNIProxy Architecture

## Overview

SNIProxy is a transparent proxy that routes TCP and UDP connections based on
hostname extraction from protocol headers: TLS SNI, DTLS SNI, HTTP Host,
HTTP/2 :authority, XMPP stream `to`, and Minecraft handshake server address.
It operates at Layer 4 (transport) while inspecting Layer 7 (application)
protocol headers to make routing decisions.

## Component Diagram

          +---------------+
          |Config:        |
          |  config_file  |
          |  username     |
          |  group        |
          |  pidfile      |
          |  resolver     |
          |  access_log   |
          +---------------+
            |          \----------\
            v                     |
    +-----------+                 v
    |Listener:  |+            +-------+             +------------+
    |  socket   ||            |Table: |+            |Backend:    |+
    |  protocol ||--has one-->|  name ||--has many->|  pattern*  ||+
    |  address  ||            +-------+|            |  address   |||
    |  fallback ||             +-------+            |  port      |||
    |  source   ||                                  +------------+||
    +-----------+|                                   +------------+|
     +-----------+                                    +------------+
        ^                                                 ^
        |             +-------------+                     |
        |             |Connection:  |+                    |
        \-references--|  state      ||+                   |
                      |  listener   |||                   |
                      |  hostname   |||                   |
                      |  client     |||                   |
                      |    socket   |||                   |
                      |    buffer   |||                   |
                      |  server     |||--selected from----/
                      |    socket   |||
                      |    buffer   |||
                      |  query      |||
                      +-------------+||
                       +-------------+|
                        +-------------+
                              |
                              v
                        +----------+
                        |Resolver: |
                        |  mode    |
                        |  queries |
                        +----------+

## Core Components

### Config

The Config structure holds global configuration and references to all listeners
and tables.

**Configuration fields:**
- `filename`: Path to configuration file
- `user`, `group`: User/group to drop privileges to
- `pidfile`: PID file path
- `resolver`: DNS resolver configuration
  - `nameservers`: List of DNS servers
  - `search`: DNS search domains
  - `mode`: IPv4/IPv6 preference (default, IPv4-only, IPv6-only, IPv4-first, IPv6-first)
  - `max_concurrent_queries`: Limit for concurrent DNS queries (default 512)
- `access_log`: Global access logger
- `listeners`: List of all configured listeners
- `tables`: List of all routing tables

**Runtime behavior:**
- Configuration can be reloaded without dropping connections
- Uses reference counting for safe config updates

### Listener

Listeners are listening service ports that accept incoming client connections.
Each listener operates independently with its own event loop watchers.

**Configuration fields:**
- `address`: Listening address and port
- `protocol`: Protocol parser (TLS, DTLS, HTTP, XMPP, Minecraft); the HTTP
  parser also recognises HTTP/2 prior-knowledge requests by their preface
- `table_name`: Name of routing table to use
- `fallback_address`: Default backend when no match found
- `source_address`: Source address for outbound connections
- `access_log`: Per-listener access log (overrides global)
- `log_bad_requests`: Whether to log malformed requests
- `reuseport`: Enable SO_REUSEPORT for parallel accept
- `transparent_proxy`: Enable IP_TRANSPARENT for source IP preservation
- `ipv6_v6only`: Enable IPV6_V6ONLY socket option
- `fallback_use_proxy_header`: Send PROXY protocol header to fallback

**Runtime fields:**
- `reference_count`: For safe removal during reload
- `watcher`: libev I/O watcher for accept events
- `backoff_timer`: Pauses accepting when the process runs out of file
  descriptors (EMFILE or ENFILE), for 2 seconds doubling up to 60
- `table`: Resolved pointer to routing table
- `accept_cb`: Accept callback function

**Operations:**
- Accepts incoming connections
- Extracts hostname from protocol headers
- Looks up backend in routing table
- Creates connection object for proxying

### Table

Tables contain routing rules that map hostnames to backend addresses.

**Configuration fields:**
- `name`: Unique table identifier
- `backend_affinity`: Choose among several resolved addresses by client
  address instead of at random

**Runtime fields:**
- `reference_count`: For safe updates during reload
- `backends`: Ordered list of backend patterns

**Lookup behavior:**
- Backends are evaluated in order
- First matching pattern wins
- Every pattern is a PCRE2 regular expression; literal hostnames are
  anchored first so that they match exactly
- Regex match limits scale with hostname length to prevent ReDoS

### Backend

Backends represent destination servers with pattern-based routing rules.

**Configuration fields:**
- `pattern`: Hostname pattern (literal or regex)
- `address`: Backend server address (hostname or IP:port)
- `use_proxy_header`: Send a PROXY protocol v1 or v2 header to this backend

**Runtime fields:**
- `pattern_re`: Compiled PCRE2 regex; every pattern is compiled, case
  insensitively, and JIT compiled when possible
- `pattern_match_data`: PCRE2 match data structure

**Pattern matching:**
- Literal hostnames (no metacharacter other than '.'): rewritten as an
  anchored regex with the dots escaped, so they only match that hostname
- Other patterns: compiled as they are, as unanchored PCRE2 regular
  expressions rather than glob wildcards
- All patterns match case insensitively
- Security: Regex match limits prevent algorithmic complexity attacks
- NUL bytes in patterns are rejected

### Connection

Connections represent active proxied sessions between client and server.

**State machine:**
```
NEW -> ACCEPTED -> PARSED -> RESOLVING -> RESOLVED -> CONNECTED
                      |                                    |
                      +-> (fallback) -> RESOLVED --------->+
                                                            |
                      +-------------------------------------+
                      v
               SERVER_CLOSED or CLIENT_CLOSED
                      |
                      v
                   CLOSED
```

**States:**
- `NEW`: Before successful accept
- `ACCEPTED`: Client connection established
- `PARSED`: Hostname extracted from protocol headers
- `RESOLVING`: DNS lookup in progress (if backend is hostname)
- `RESOLVED`: Backend address obtained
- `CONNECTED`: Bidirectional proxy active
- `SERVER_CLOSED`: Server closed, draining server-to-client buffer
- `CLIENT_CLOSED`: Client closed, draining client-to-server buffer
- `CLOSED`: Both sockets closed, connection can be freed

**Fields:**
- `client`: Client socket, buffer, and address info
- `server`: Server socket, buffer, and address info
- `listener`: Reference to parent listener
- `hostname`: Extracted hostname from protocol headers (with length)
- `header_len`: Length of the PROXY header prepended to the client buffer,
  which the parser skips and which is dropped again for a backend that does
  not take it
- `query_handle`: DNS resolution handle (if needed)
- `idle_timer`: Connection timeout watcher
- `established_timestamp`: For connection duration logging
- `use_proxy_header`: Whether to send PROXY header to backend
- **Memory tracking (0.9.0)**: Connections participate in global memory accounting,
  tracking both connection structure size and associated buffer memory for
  operational visibility

**Client and Server sub-structures:**
- `addr`, `local_addr`: Socket addresses
- `addr_len`, `local_addr_len`: Address lengths
- `watcher`: libev I/O watcher
- `buffer`: Dynamic ring buffer for data

### Buffer

Dynamic ring buffers for efficient data transfer with minimal copying.

**Fields:**
- `buffer`: Underlying memory (power-of-2 size for efficient modulo)
- `min_size`: Minimum buffer size
- `size_mask`: Bit mask for buffer size (e.g., 8191 for 8KB buffer)
- `head`: Index of first byte
- `len`: Number of bytes in buffer
- `max_size`: Hard cap to prevent unbounded growth
- `last_recv`, `last_send`: Timestamps for timeout detection
- `tx_bytes`, `rx_bytes`: Transfer statistics

**Features:**
- Power-of-2 sizing for fast modulo operations
- Automatic growth when full (up to max_size)
- Shrinking when underutilized
- Zero-copy operations where possible
- Overflow protection: `buf->len + min_room` wraparound detection
- **Performance optimization (0.9.0)**: Buffers are shrunk by a timer that runs
  every second rather than on each I/O event; an event only moves the
  connection within a deadline-ordered queue of shrink candidates, and only
  when both of its buffers are empty
- **Memory tracking (0.9.0)**: A global memory observer, called on every buffer
  allocation, resize and free, tracks total buffer memory across all
  connections. Above 64 MiB it also shrinks idle buffers, at most every 0.25
  seconds
- **Reliability (0.9.6)**: Buffer growth refuses to exceed SIZE_MAX/2 and now
  closes the offending connection instead of silently leaving buffers in an
  inconsistent state.
- **Bounded shrink queues (0.9.6)**: Shrink candidate lists stay capped at 4096
  entries and force-shrink the oldest 10% once full, preventing internal
  bookkeeping from consuming unbounded RAM.
- **Corruption detection (0.9.6)**: Buffer pool freelist nodes embed magic
  numbers so corrupt pointers are detected before dereferencing cached links.

### Protocol

Protocol handlers parse application-layer headers to extract hostnames.

**Structure:**
- `name`: Protocol identifier ("tls", "dtls", "http", "xmpp", "minecraft")
- `default_port`: Default port for protocol
- `sock_type`: Socket type (SOCK_STREAM for TCP, SOCK_DGRAM for UDP)
- `parse_packet`: Function pointer to header parser
- `abort_message`: Message sent to client on parse failure
- `abort_message_len`: Length of abort message

**Supported protocols:**

1. **TLS**: Extracts SNI from ClientHello (TCP)
   - Parses TLS 1.0 through 1.3 ClientHellos, but refuses those below TLS 1.2
     unless `-T` lowers the minimum
   - Validates extension format
   - Limits ClientHello extension lists to 64 entries (0.9.6) to stop CPU
     exhaustion from thousands of tiny extensions
   - Rejects embedded NUL bytes in server names
   - Minimum client version can be configured with `-T`
   - Detects and rejects client renegotiation attempts

2. **DTLS**: Extracts SNI from DTLS ClientHello (UDP)
   - Parses DTLS 1.0 and 1.2 record layer format
   - Shares SNI extension parsing with TLS via `sni_parse.h`
   - Cannot read SNI from a fragmented ClientHello, which is treated as a
     request without a hostname: it goes to the fallback, or is dropped
     when there is none
   - Per-session connected server sockets with idle timeout
   - Supports source address binding and transparent proxy mode

3. **HTTP**: Extracts Host header from HTTP/1.x requests
   - Reads only the Host header; the request line is skipped, so neither
     the method nor an absolute URI plays a part
   - Case-insensitive header matching
   - Rejects a second Host header and strips a port from the value
   - Enforces a header count limit (0.9.6), `HTTP_DEFAULT_MAX_HEADERS` (100)
     unless `http_max_headers` sets another value from 1 to 4096, to prevent
     CPU exhaustion from adversarial header floods

4. **HTTP/2**: Extracts :authority pseudo-header from HTTP/2 requests, as part
   of the HTTP protocol when a request starts with the HTTP/2 preface
   - Parses client preface and SETTINGS frames
   - HPACK decompression with dynamic table
   - Handles HEADERS and CONTINUATION frames
   - Huffman decoding support
   - **Performance optimization (0.9.0)**: Static HPACK table uses precomputed
     name/value lengths and binary search for header name lookups, eliminating
     repeated strlen calls and linear table scans
   - Security limits:
     - Max header block size: 64KB
     - Max dynamic table size per connection: 64KB
     - Max aggregate dynamic table size: 4MB
     - Prevents memory exhaustion attacks

5. **XMPP**: Extracts `to` attribute from stream opening
   - Parses initial `<stream:stream to="...">` element
   - Supports STARTTLS negotiation (transparent to proxy)
   - Maximum header size: 4096 bytes

6. **Minecraft**: Extracts server address from handshake packet
   - Parses VarInt-framed handshake packet
   - Strips FML markers and BungeeCord data after NUL bytes
   - Default port: 25565

### Resolver

Asynchronous DNS resolver for backend addresses specified as hostnames.

**Features:**
- Configurable nameservers and search domains
- IPv4/IPv6 preference modes
- Concurrent query limiting to prevent resource exhaustion
- Integration with libev event loop
- Thread-safe query list with mutex protection
- DNS-over-TLS upstreams via `dot://address/hostname` entries with certificate
  verification against the system trust store
- **Security enhancements (0.9.0 -> 0.9.6)**: The IDs that match resolver
  requests and results between the main process and the resolver process
  moved from linear counters to xorshift32 and now to arc4random(), unique
  among queries in flight; the IDs in the DNS packets themselves come from
  c-ares. Each connection records whether it holds a slot of the DNS query
  limits (`dns_query_acquired`), so a slot is released exactly once.
- **Robustness (0.9.0 -> 0.9.6)**: Async-signal-safe signal handlers and
  overflow guards remain, and resolver restart/shutdown now uses
  mutex-protected flags plus dedicated release helpers to prevent counter drift
  or use-after-free bugs during teardown.
- **DNSSEC default (0.9.7)**: Resolver blocks default to `dnssec_validation
  relaxed`, which only turns on EDNS0 in c-ares. Nothing requests or checks
  the AD flag, which c-ares cannot report, and `strict` is accepted but
  treated as relaxed.
- **Search domains (0.9.8)**: Entries are treated as literal suffixes appended
  during lookups; they are no longer parsed as hostnames, avoiding surprise
  validation failures for split-horizon environments.

**Modes:**
- `RESOLV_MODE_DEFAULT`: No `mode` configured; A and AAAA are queried in
  parallel and the first family to answer with records is used
- `RESOLV_MODE_IPV4_ONLY`: A records only
- `RESOLV_MODE_IPV6_ONLY`: AAAA records only
- `RESOLV_MODE_IPV4_FIRST`: Prefer A records, answering as soon as they arrive
- `RESOLV_MODE_IPV6_FIRST`: Prefer AAAA records, answering as soon as they arrive

### Logger

Flexible logging system supporting syslog and file-based logging.

**Features:**
- Per-listener access logs
- Global error log
- Standard syslog severity levels (emerg through debug)
- Log rotation support via SIGHUP
- Privilege separation: logger process runs as configured user/group

**Log levels:**
- `LOG_EMERG` (0) through `LOG_DEBUG` (7)
- Configurable minimum priority filtering

### Address

Abstraction for network addresses supporting both IP addresses and hostnames.

**Types:**
- Numeric IPv4/IPv6 addresses with port
- Hostnames with port (requires DNS resolution)
- Unix domain sockets (if configured)
- Wildcard `*`, optionally with a port, valid only as a table backend,
  where it means the hostname the client asked for; listeners and
  fallbacks refuse it

**Features:**
- Unified representation for configuration and runtime
- Comparison and display functions
- Port manipulation
- Address family detection

## Data Flow

### Connection Establishment

1. **Accept**: Listener accepts new client connection
   - Creates Connection object in NEW state
   - Transitions to ACCEPTED
   - Sets up client I/O watcher

2. **Parse**: Read initial data from client
   - Protocol parser extracts hostname
   - Sanitizes hostname: rejects control characters, spaces, non-ASCII
     bytes and anything but letters, digits, '-', '_' and '.', lowercases
     it and strips trailing dots
   - Validates hostname length and format, with labels of at most 63 bytes
   - Transitions to PARSED

3. **Lookup**: Find backend for hostname
   - Queries listener's routing table
   - Evaluates backend patterns in order
   - Uses fallback address if no match
   - Records whether to use PROXY header, and if one may be needed puts it
     in front of the buffered client data

4. **Resolve**: Obtain backend IP address
   - If backend is IP address: transitions to RESOLVED immediately
   - If backend is hostname:
     - Transitions to RESOLVING
     - Submits DNS query with callback
     - Waits asynchronously for result
     - Transitions to RESOLVED on completion

5. **Connect**: Establish server connection
   - Checks the backend address against `backend_acl`, closing the
     connection if it is denied
   - Creates outbound socket
   - Optionally binds to source address
   - Drops the PROXY header again if this backend does not take one
   - Initiates non-blocking connect and transitions to CONNECTED at once
   - Once the socket is writable, sends the buffered client data, which
     starts with the PROXY header when there is one

### Data Transfer

Once CONNECTED, the connection enters steady-state proxying:

1. **Client -> Server**: When client data available
   - `buffer_recv()` from client socket into client buffer
   - `buffer_send()` from client buffer to server socket
   - Handle EAGAIN/EWOULDBLOCK for non-blocking I/O

2. **Server -> Client**: When server data available
   - `buffer_recv()` from server socket into server buffer
   - `buffer_send()` from server buffer to client socket
   - Handle EAGAIN/EWOULDBLOCK for non-blocking I/O

3. **Flow control**: libev watchers
   - Enable read watcher when buffer has room
   - Enable write watcher when buffer has data
   - Disable watchers when not needed (reduce CPU usage)

### Connection Teardown

1. **Partial close**: One side closes
   - Transitions to SERVER_CLOSED or CLIENT_CLOSED
   - Continues flushing remaining buffer data
   - Closes other socket when buffer empty

2. **Full close**: Both sides closed
   - Transitions to CLOSED
   - Logs connection statistics (duration, bytes transferred)
   - Frees all resources (buffers, watchers, query handles)
   - Removes from connection list

## Security Features

### Input Validation

- **Hostname sanitization**: Rejects hostnames containing control characters
  or other unexpected bytes rather than removing them, validates length
- **NUL byte rejection**: The TLS, DTLS, HTTP, HTTP/2 and XMPP parsers reject
  embedded NUL bytes; the Minecraft parser cuts the address at the first NUL,
  after which FML and BungeeCord add their own data
- **Buffer overflow protection**: Strict bounds checking in all parsers
  - TLS: Validates ClientHello structure and extension lengths
  - HTTP: Limits the header count and the Host value length
  - HTTP/2: Frame size limits, header block size limits

### Denial of Service Protection

- **Regex DoS prevention**:
  - Match limits scale with hostname length
  - Per-request limits injected into PCRE2 contexts
  - Prevents catastrophic backtracking

- **Request guardrails (0.9.6)**:
  - HTTP parsers enforce `http_max_headers` (default 100) so
    attacker-controlled header floods cannot pin CPU in linear scans
  - TLS ClientHello parsers cap extension lists at 64 entries to avoid walking
    unbounded extension tables

- **Memory limits**:
  - Buffer max_size prevents unbounded growth
  - HTTP/2 dynamic table size caps (per-connection and global)
  - DNS query concurrency limits
  - Shrink candidate queues capped at 4096 entries with forced trimming when
    full (0.9.6)
  - Buffer growth refuses to exceed SIZE_MAX/2 and closes the offending
    connection (0.9.6)

- **Rate limiting**:
  - Per-IP connection rate limiting with token bucket algorithm
  - **Performance optimization (0.9.0)**: IPv4 fast path with cached 32-bit address
    comparison, and a bucket that is hit moves to the front of its hash chain.
    Buckets are only evicted by age: at most once a minute a sweep drops
    those idle for more than 300 seconds
  - **Collision defense (0.9.6)**: the 65536 buckets are hashed with an
    arc4random() seed (a multiply-xorshift mix for IPv4, a SplitMix64-derived
    mixer over the masked prefix for IPv6). Entries with equal hashes are
    told apart by their address, and a connection is refused only when a
    lookup walks past 32 entries of one chain, so collision spraying cannot
    bypass the limiter
  - Accept backoff when file descriptors run out, from the first EMFILE or
    ENFILE, growing from 2 to 60 seconds
  - Idle connection timeouts
- **Configuration hardening (0.9.7)**: sniproxy refuses to load
  configuration files that are readable or writable by group/other users,
  ensuring accidental chmod mistakes do not leak secrets when starting or
  reloading the daemon.
- **Configuration hardening (0.9.8)**: Reloads repeat the permission checks,
  all configured paths must be absolute, resolver cancellation takes the
  query list mutex, and temporary connection dumps are created by
  `mkostemp()` with O_CLOEXEC, whose O_CREAT|O_EXCL already refuses to
  follow a symlink.

### PROXY Protocol Support

SNIProxy can prepend PROXY protocol v1/v2 headers to backend connections,
preserving original client IP and port. Configurable per backend in a table,
and for each listener's fallback.

**Use cases:**
- Passing client source info to backend servers
- Integration with HAProxy and other PROXY-aware services
- Required for fallback backends when transparent proxy unavailable

**Performance optimization (0.9.0)**: PROXY v1 header composition uses single-pass
buffer assembly, reducing the number of buffer operations required

### Privilege Separation

- Binds to privileged ports as root
- Drops to configured user/group after initialization
- Logger process runs with reduced privileges
- Separate processes communicate via unix socketpairs with ChaCha20-Poly1305 encryption

## Configuration and Reload

### Initial Load

1. Parse the configuration file, creating tables and backends (compiling
   their regexes) and the loggers; the logger process is forked here
2. On OpenBSD, unveil the paths the process needs and pledge
3. Daemonize and write the pidfile, unless running with `-f`
4. Start the binder process
5. Apply the file descriptor and connection limits
6. Create listeners, bind sockets
7. Drop privileges
8. Start the resolver process
9. Install the seccomp filter (Linux) or limit descriptor rights
   (FreeBSD), then enter the event loop

### Reload (SIGHUP)

1. Parse the new configuration file; if it fails to parse or fails the
   permission check, the running configuration is kept
2. Swap the backend list of each existing table for the new one in place,
   and add new tables
3. Compare listeners by address:
   - Same address: updated in place, keeping the socket; `tcp_fastopen`,
     `reuseport` and `ipv6_v6only` changes are ignored with a warning.
     Only a change between TCP and UDP replaces the listener, binding the
     new socket before the old one is closed
   - New listeners: bound and started
   - Removed listeners: stopped
4. Apply the other global settings (limits, buffer caps, backend ACL,
   logs); user, group, pidfile and the resolver's servers, search domains,
   mode and DNSSEC setting wait for a restart
5. Use reference counting to defer freeing old objects
6. Connections that are already routed keep their backend; those still
   waiting for their request are routed with the new tables, and new
   buffer limits apply to existing connections
7. New connections use the new configuration

## Performance Considerations

- **Event-driven**: libev for efficient I/O multiplexing
- **Minimal copying**: Ring buffers and vectored I/O; SO_SPLICE zero-copy on OpenBSD
- **SO_REUSEPORT**: Multiple processes can accept on same port
- **Buffer pooling**: Freed 8, 16 and 32 KiB buffer blocks are kept for
  reuse; connection structures themselves are allocated and freed each time
- **Compiled regexes**: One-time compilation, cached for all lookups

### Performance Optimizations in 0.9.0

- **Table-level hostname cache**: 256-entry FNV-1a hash cache at the table level
  eliminates repeated PCRE2 regex evaluations for the same hostname
- **HTTP/2 HPACK**: Precomputed static table entry lengths and binary search for
  header names eliminate strlen calls and linear table scans
- **Buffer management**: A once-per-second shrink timer does the resizing; I/O
  callbacks only keep the connection's place in the shrink candidate queue
- **Rate limiting**: IPv4 fast path with 32-bit integer comparison and
  move-to-front hash chains improves high-volume connection acceptance
- **Protocol parsers**: TLS, HTTP, and HTTP/2 parsers use compile-time length
  constants and optimized data structures to minimize per-request overhead
- **PROXY protocol**: Single-pass header composition reduces buffer operations
- **Memory accounting**: Global tracking costs one observer call per buffer
  allocation, resize or free, and shrinks idle buffers under memory pressure
- **Socket state caching**: Connection callbacks cache socket open state to avoid
  repeated checks

## Testing

The codebase includes comprehensive tests:
- Unit tests for all major components (buffer, TLS, DTLS, HTTP, HTTP/2, XMPP,
  Minecraft, table, address, config, resolver, binder, seccomp)
- Fuzz tests for TLS, DTLS, HTTP/2, XMPP, Minecraft, hostname, address, config,
  listener ACL, IPC crypto, and resolver parsers
- Integration tests for end-to-end listener and routing validation
- Address and configuration parsing tests
