# Fuzzing TLS and HTTP/2 parsers

These harnesses target the most complicated parsers in sniproxy – the TLS
ClientHello/SNI parser and the HTTP/2 HPACK header decoder. They are designed
for use with libFuzzer (available in clang). Run the commands below from the
repository root to build the fuzzers with AddressSanitizer and
UndefinedBehaviorSanitizer enabled.

For a one-command setup, run `tests/fuzz/run_fuzz.sh`. The script builds
both harnesses with libFuzzer plus AddressSanitizer/UndefinedBehaviorSanitizer
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

## Continuous fuzzing

Travis CI now runs `tests/fuzz/run_fuzz.sh` (when building with clang) with a
short `FUZZ_RUNTIME` budget on every push. Any crash or sanitizer finding in the
TLS or HTTP/2 harnesses fails the build, giving early warning about boundary
regressions.
