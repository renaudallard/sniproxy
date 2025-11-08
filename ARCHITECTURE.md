# SNIProxy Architecture

## Overview

SNIProxy is a transparent TLS/HTTP proxy that routes connections based on the
Server Name Indication (SNI) extension in TLS handshakes or the Host header in
HTTP requests. It operates at Layer 4 (transport) while inspecting Layer 7
(application) protocol headers to make routing decisions.

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
  - `max_concurrent_queries`: Limit for concurrent DNS queries (default 256)
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
- `protocol`: Protocol parser (TLS, HTTP, HTTP/2)
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
- `backoff_timer`: Exponential backoff for accept errors
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
- `use_proxy_header`: Send PROXY protocol v1/v2 header to backends

**Runtime fields:**
- `reference_count`: For safe updates during reload
- `backends`: Ordered list of backend patterns

**Lookup behavior:**
- Backends are evaluated in order
- First matching pattern wins
- Supports exact string matching and PCRE/PCRE2 regular expressions
- Regex match limits scale with hostname length to prevent ReDoS

### Backend

Backends represent destination servers with pattern-based routing rules.

**Configuration fields:**
- `pattern`: Hostname pattern (literal or regex)
- `address`: Backend server address (hostname or IP:port)
- `use_proxy_header`: Override table's PROXY header setting

**Runtime fields:**
- `pattern_re`: Compiled PCRE/PCRE2 regex (if pattern contains wildcards)
- `pattern_match_data`: PCRE2 match data structure

**Pattern matching:**
- Literal strings: Exact hostname match
- Regular expressions: PCRE/PCRE2 patterns with wildcards (*, ., etc.)
- Security: Regex match limits prevent algorithmic complexity attacks
- NUL bytes in patterns are rejected
- **Performance optimization (0.9.0)**: Per-backend cache stores the most recent
  hostname lookup result, allowing repeated lookups to skip expensive PCRE regex
  evaluation entirely

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
- `SERVER_CLOSED`: Server closed, draining client-to-server buffer
- `CLIENT_CLOSED`: Client closed, draining server-to-client buffer
- `CLOSED`: Both sockets closed, connection can be freed

**Fields:**
- `client`: Client socket, buffer, and address info
- `server`: Server socket, buffer, and address info
- `listener`: Reference to parent listener
- `hostname`: Extracted hostname from protocol headers (with length)
- `header_len`: Length of inspected protocol header
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
- **Performance optimization (0.9.0)**: Periodic shrink timer reduces per-event
  timestamp operations, eliminating unnecessary buffer size checks on every I/O event
- **Memory tracking (0.9.0)**: Global memory observer tracks total buffer memory
  usage across all connections, providing visibility into peak memory consumption

### Protocol

Protocol handlers parse application-layer headers to extract hostnames.

**Structure:**
- `name`: Protocol identifier ("tls", "http", "http2")
- `default_port`: Default port for protocol
- `parse_packet`: Function pointer to header parser
- `abort_message`: Message sent to client on parse failure
- `abort_message_len`: Length of abort message

**Supported protocols:**

1. **TLS**: Extracts SNI from ClientHello
   - Supports TLS 1.0 through 1.3
   - Validates extension format
   - Rejects embedded NUL bytes in server names
   - Minimum client version can be configured
   - Detects and rejects client renegotiation attempts

2. **HTTP**: Extracts Host header from HTTP/1.x requests
   - Parses GET/POST/HEAD and other methods
   - Case-insensitive header matching
   - Handles absolute URIs and Host headers

3. **HTTP/2**: Extracts :authority pseudo-header from HTTP/2 requests
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

### Resolver

Asynchronous DNS resolver for backend addresses specified as hostnames.

**Features:**
- Configurable nameservers and search domains
- IPv4/IPv6 preference modes
- Concurrent query limiting to prevent resource exhaustion
- Integration with libev event loop
- Thread-safe query list with mutex protection
- **Security enhancement (0.9.0)**: DNS query IDs generated using xorshift32 PRNG
  (seeded from time and PID) instead of linear counter, preventing timing-based
  query ID prediction attacks
- **Robustness (0.9.0)**: Async-signal-safe signal handlers, integer overflow
  protection in memory operations, and proper cleanup to prevent memory leaks

**Modes:**
- `RESOLV_MODE_DEFAULT`: System default behavior
- `RESOLV_MODE_IPV4_ONLY`: A records only
- `RESOLV_MODE_IPV6_ONLY`: AAAA records only
- `RESOLV_MODE_IPV4_FIRST`: Prefer A records
- `RESOLV_MODE_IPV6_FIRST`: Prefer AAAA records

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
- Wildcard addresses for listening

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
   - Sanitizes hostname (removes control chars, trailing dots)
   - Validates hostname length and format
   - Transitions to PARSED

3. **Lookup**: Find backend for hostname
   - Queries listener's routing table
   - Evaluates backend patterns in order
   - Uses fallback address if no match
   - Records whether to use PROXY header

4. **Resolve**: Obtain backend IP address
   - If backend is IP address: transitions to RESOLVED immediately
   - If backend is hostname:
     - Transitions to RESOLVING
     - Submits DNS query with callback
     - Waits asynchronously for result
     - Transitions to RESOLVED on completion

5. **Connect**: Establish server connection
   - Creates outbound socket
   - Optionally binds to source address
   - Initiates non-blocking connect
   - Sends buffered client data (including parsed header)
   - Sends PROXY protocol header if configured
   - Transitions to CONNECTED

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

- **Hostname sanitization**: Removes control characters, validates length
- **NUL byte rejection**: Protocol parsers reject embedded NUL bytes
- **Buffer overflow protection**: Strict bounds checking in all parsers
  - TLS: Validates ClientHello structure and extension lengths
  - HTTP: Limits header sizes, validates method and URI formats
  - HTTP/2: Frame size limits, header block size limits

### Denial of Service Protection

- **Regex DoS prevention**:
  - Match limits scale with hostname length
  - Per-request limits injected into PCRE/PCRE2 contexts
  - Prevents catastrophic backtracking

- **Memory limits**:
  - Buffer max_size prevents unbounded growth
  - HTTP/2 dynamic table size caps (per-connection and global)
  - DNS query concurrency limits

- **Rate limiting**:
  - Per-IP connection rate limiting with token bucket algorithm
  - **Performance optimization (0.9.0)**: IPv4 fast path with cached 32-bit address
    comparison and LRU eviction moves recently-used entries to front of hash chains
  - Accept backoff timer on repeated errors
  - Idle connection timeouts

### PROXY Protocol Support

SNIProxy can prepend PROXY protocol v1/v2 headers to backend connections,
preserving original client IP and port. Configurable per-table or per-backend.

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
- Separate processes communicate via pipes

## Configuration and Reload

### Initial Load

1. Parse configuration file
2. Create tables and backends, compile regexes
3. Create listeners, bind sockets
4. Initialize resolver
5. Drop privileges
6. Enter event loop

### Reload (SIGHUP)

1. Parse new configuration file
2. Create new tables and listeners
3. Compare with existing configuration:
   - Unchanged listeners: keep running
   - Modified listeners: stop old, start new
   - New listeners: start
   - Removed listeners: stop
4. Update table references atomically
5. Use reference counting to defer freeing old objects
6. Existing connections continue with old configuration
7. New connections use new configuration

## Performance Considerations

- **Event-driven**: libev for efficient I/O multiplexing
- **Zero-copy**: splice() on Linux (if available)
- **Minimal copying**: Ring buffers, vectored I/O
- **SO_REUSEPORT**: Multiple processes can accept on same port
- **Connection pooling**: Reuses connection structures
- **Compiled regexes**: One-time compilation, cached for all lookups

### Performance Optimizations in 0.9.0

- **Pattern match caching**: Backends cache the most recent hostname lookup result,
  eliminating repeated PCRE regex evaluations for the same hostname
- **HTTP/2 HPACK**: Precomputed static table entry lengths and binary search for
  header names eliminate strlen calls and linear table scans
- **Buffer management**: Periodic shrink timer reduces per-event operations,
  eliminating unnecessary timestamp checks on every I/O callback
- **Rate limiting**: IPv4 fast path with 32-bit integer comparison and LRU hash
  chain management improves high-volume connection acceptance
- **Protocol parsers**: TLS, HTTP, and HTTP/2 parsers use compile-time length
  constants and optimized data structures to minimize per-request overhead
- **PROXY protocol**: Single-pass header composition reduces buffer operations
- **Memory accounting**: Global tracking provides operational visibility without
  per-operation overhead
- **Socket state caching**: Connection callbacks cache socket open state to avoid
  repeated checks

## Testing

The codebase includes comprehensive tests:
- Unit tests for all major components (buffer, tls, http, http2, table, etc.)
- Fuzz tests for TLS and HTTP/2 parsers
- Integration tests for listener and backend lookup
- Address and configuration parsing tests
