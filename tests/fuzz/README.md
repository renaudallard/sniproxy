# Fuzzing Infrastructure

This directory contains comprehensive fuzzing harnesses for sniproxy using libFuzzer
with AddressSanitizer and UndefinedBehaviorSanitizer.

## Available Fuzzers

| Fuzzer | Target | Description |
|--------|--------|-------------|
| `tls_fuzz` | src/tls.c | TLS ClientHello parsing and SNI extraction |
| `http2_fuzz` | src/http2.c | HTTP/2 HPACK header parsing |
| `http_fuzz` | src/http.c | HTTP/1.x request parsing and Host header extraction |
| `hostname_fuzz` | src/hostname_sanitize.h | Hostname validation and sanitization |
| `cfg_tokenizer_fuzz` | src/cfg_tokenizer.c | Configuration file tokenization |
| `address_fuzz` | src/address.c | Address parsing/formatting logic |
| `ipc_crypto_fuzz` | src/ipc_crypto.c | IPC encryption/decryption with ChaCha20-Poly1305 |
| `table_lookup_fuzz` | src/table.c | Backend table matching and regex routing |
| `listener_acl_fuzz` | src/listener.c | Listener ACL CIDR evaluation |
| `resolver_response_fuzz` | src/resolv.c | DNS resolver address handling / edge-case responses |
| `ipc_msg_fuzz` | src/ipc_crypto.c | IPC message send/recv framing over Unix sockets |
| `config_fuzz` | init_config()/config.c | Full configuration parsing/validation pipeline |
| `ipc_state_fuzz` | ipc_crypto state machine | Exercises channel init, role swaps, sealing, and opens |

## Quick Start

For a one-command setup, run `tests/fuzz/run_fuzz.sh`. The script builds
all harnesses with libFuzzer plus AddressSanitizer/UndefinedBehaviorSanitizer
and runs them against the seed corpora under `tests/fuzz/corpus`. Override
`FUZZ_RUNTIME` (seconds), `OUT_DIR`, or set `RUN_FUZZ=0` to just build the
binaries without executing them.

The helper will skip itself if the selected compiler lacks libFuzzer
support; set `FUZZ_OPTIONAL=0` to make that a hard error (the CI default).


## TLS fuzzer

```
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/tls_fuzz.c \
    src/tls.c
```

## HTTP/2 fuzzer

```
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/http2_fuzz.c \
    src/http2.c
```

Replace the sanitizer list or add `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`
if your toolchain expects it. The resulting binaries can then be run directly
with a seed corpus directory.

## Example Build Commands

### HTTP fuzzer

```bash
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/http_fuzz.c \
    src/http.c
```

### Hostname fuzzer

```bash
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/hostname_fuzz.c
```

### Config tokenizer fuzzer

```bash
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/cfg_tokenizer_fuzz.c \
    src/cfg_tokenizer.c
```

### IPC crypto fuzzer

```bash
clang -fsanitize=fuzzer,address,undefined -Isrc \
    tests/fuzz/ipc_crypto_fuzz.c \
    src/ipc_crypto.c \
    -lcrypto
```

## CI/CD Integration

### Pull Request Fuzzing

The `build-and-fuzz.yml` GitHub Actions workflow runs on every push and pull request:

- Builds all fuzzers with AddressSanitizer and UndefinedBehaviorSanitizer
- Runs each fuzzer for 120 seconds
- Uploads any crash artifacts for debugging
- Uploads the evolved corpus for reuse

### Continuous Fuzzing

The `continuous-fuzzing.yml` workflow runs daily at 02:00 UTC:

- Runs each fuzzer for 1 hour (60 minutes per fuzzer)
- Downloads and uses the corpus from previous runs
- Automatically creates GitHub issues when crashes are found
- Uploads crash artifacts and updated corpus with 90-day retention

You can also manually trigger continuous fuzzing from the GitHub Actions tab.

## Environment Variables

- `FUZZ_CC`: Compiler to use (default: `clang`)
- `FUZZ_RUNTIME`: Seconds to run each fuzzer (default: `30`)
- `FUZZ_OPTIONAL`: Skip if libFuzzer unavailable (default: `1`)
- `RUN_FUZZ`: Run fuzzers after building (default: `1`, set to `0` to build only)
- `FUZZ_VERBOSE`: Emit progress logs (default: `1`, set to `0` for error-only output)
- `OUT_DIR`: Output directory for binaries (default: `tests/fuzz/bin`)
- `CORPUS_ROOT`: Corpus directory (default: `tests/fuzz/corpus`)

## Interpreting Crashes

If a fuzzer finds a crash, it saves the input to a file like `crash-<hash>` and exits.
You can reproduce the crash locally:

```bash
./tests/fuzz/bin/http_fuzz crash-abc123
```

The fuzzer will print a stack trace showing where the crash occurred. Use AddressSanitizer
output to identify memory errors like buffer overflows, use-after-free, etc.

## Security

Fuzzing is a critical security testing component:

- All parsers handling untrusted network input have fuzzers
- AddressSanitizer catches memory corruption bugs
- UndefinedBehaviorSanitizer catches undefined behavior
- Continuous fuzzing provides ongoing security monitoring
- All crashes are treated as potential security vulnerabilities
