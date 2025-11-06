# Fuzzing TLS and HTTP/2 parsers

These harnesses target the most complicated parsers in sniproxy – the TLS
ClientHello/SNI parser and the HTTP/2 HPACK header decoder. They are designed
for use with libFuzzer (available in clang). Run the commands below from the
repository root to build the fuzzers with AddressSanitizer and
UndefinedBehaviorSanitizer enabled.

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
