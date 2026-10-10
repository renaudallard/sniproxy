# Public DNS resolvers over each transport

Measurements of Quad9, Cloudflare and Google over UDP, TCP, DNS over TLS
(DoT), DNS over HTTPS on HTTP/2 (DoH) and HTTP/3 (DoH3), and DNS over
QUIC (DoQ), made while looking at how the `dot://` nameservers of the
resolver behave. They are a snapshot from one place on one day, not a
benchmark.

## Setup

- Client: an OpenBSD 7.9 arm64 host in Paris with direct access to port
  53, IPv4 only. Median UDP answer time for a cached name: Quad9 0 ms,
  Cloudflare 2 ms, Google 5 ms.
- Date: 2026-10-09, 17:13 to 18:13 CEST.
- Servers: 9.9.9.9 and 149.112.112.112 (TLS name dns.quad9.net),
  1.1.1.1 and 1.0.0.1 (cloudflare-dns.com), 8.8.8.8 and 8.8.4.4
  (dns.google). DoQ was only tried on Quad9, the only one of the three
  that offers it. All three answer DoH over HTTP/3.
- Queries: type A, recursion desired, EDNS0 with a 1232 byte buffer,
  5 seconds allowed for each answer, providers interleaved.
- Names, three kinds:
  - cached: example.com, www.google.com, www.wikipedia.org,
    www.cloudflare.com, www.apple.com, www.microsoft.com
  - nx: a random label under openbsd.org, netbsd.org, freebsd.org,
    kernel.org or debian.org, answered NXDOMAIN
  - wild: a random label under sslip.io, which exists but can never be
    in the cache
- Patterns, for each server, transport and kind of name:
  - one: 20 connections with one query each
  - seq: 10 connections with 6 queries each, one at a time, 300 ms apart
  - pipe: 10 connections with 6 queries each, all sent at once

That is 288 runs and 13,440 queries. A query counts as not answered when
no answer came within 5 seconds, or when it could not be sent because
the server had already closed the connection (72 queries).

## Queries not answered

Each cell covers both addresses of the provider and all three patterns:
280 queries in the Quad9 columns, 840 in the Cloudflare and Google
columns, which take the three kinds of name together.

| Transport | Quad9 cached | Quad9 nx | Quad9 wild | Cloudflare | Google |
|-----------|-------------:|---------:|-----------:|-----------:|-------:|
| UDP       | 0            | 2 (0.7%) | 0          | 0          | 0      |
| TCP       | 8 (2.9%)     | 43 (15.4%) | 49 (17.5%) | 0        | 3 (0.4%) |
| DoT       | 19 (6.8%)    | 76 (27.1%) | 60 (21.4%) | 0        | 0      |
| DoH       | 0            | 8 (2.9%) | 1 (0.4%)   | 0          | 0      |
| DoH3      | 3 (1.1%)     | 12 (4.3%) | 24 (8.6%) | 0          | 0      |
| DoQ       | 3 (1.1%)     | 15 (5.4%) | 8 (2.9%)  | not offered | not offered |

Cloudflare answered all 4,200 of its queries and Google all but 3 of
4,200, lost when it closed one TCP connection during a run with nx
names. Every answer carried the expected rcode: NOERROR for cached and
wild names, NXDOMAIN for nx names.

## Quad9 on names it has not cached

Not answered, by pattern, nx and wild names together:

| Transport | one (80) | seq (240) | pipe (240) |
|-----------|---------:|----------:|-----------:|
| UDP       | 0        | 2         | 0          |
| TCP       | 6        | 26        | 60         |
| DoT       | 3        | 53        | 80         |
| DoH       | 0        | 6         | 3          |
| DoH3      | 10       | 15        | 11         |
| DoQ       | 5        | 11        | 7          |

How the queries were lost:

- TCP and DoT: Quad9 closes the whole connection, with a FIN or a TLS
  close_notify, about 10 ms after a query for a name it has not cached.
  Every query still waiting on that connection is lost, which is why
  pipelined queries fare worst.
- DoQ and DoH3: the stream of that one query is reset with error code
  0x5; the other queries on the connection are answered.
- DoH on HTTP/2: 8 queries were lost to a closed connection and 1 timed
  out.
- UDP: 2 queries got no reply at all.

Both Quad9 addresses behaved the same way. Earlier, smaller runs from a
network reaching Quad9's Frankfurt nodes saw the same thing: of 30
queries for fresh names, 6 to 9 lost their connection over plain TCP and
4 over DoT, while all 30 were answered over UDP.

## Answer times

Median of the per-run median answer time over UDP, in ms:

| Names  | Quad9 | Cloudflare | Google |
|--------|------:|-----------:|-------:|
| cached | 0     | 2          | 5      |
| nx     | 7     | 140        | 27     |
| wild   | 34    | 35         | 36     |

## What this means for sniproxy

sniproxy opens a new DoT connection for each lookup that c-ares does not
answer from its cache, sends one query on it and closes it once
answered. With Quad9 as a `dot://` nameserver about 4% of lookups of
names Quad9 has not cached lose their connection (3 of 80 in the "one"
pattern above), and c-ares retries them, which costs a new TCP and TLS handshake. Keeping a connection open
for several lookups would make it worse: Quad9 drops every query waiting
on a connection it closes. Cloudflare and Google showed no such losses
over DoT.
