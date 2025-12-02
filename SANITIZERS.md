# Memory Sanitizers Guide

This document explains how to use AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer with sniproxy. Sanitizer support is built into `./configure` and is exercised by GitHub Actions on every push and pull request via `.github/workflows/sanitizers.yml`.

## Quick facts
- Configure flags: `--enable-asan`, `--enable-msan`, `--enable-ubsan`, `--enable-tsan`; `--enable-asan --enable-ubsan` is supported for combined coverage.
- Mutual exclusions: ASAN, MSAN, and TSAN cannot be combined. Configure fails fast with `Cannot enable multiple memory sanitizers (ASAN/MSAN/TSAN) simultaneously`.
- Hardening: when a sanitizer is enabled, configure automatically disables conflicting hardening flags (`-fstack-protector-strong`, `-fcf-protection`, PIE).
- CI coverage: four jobs (ASAN, UBSAN, ASAN+UBSAN, MSAN) run on every push/PR. MSAN builds and caches instrumented dependencies so the first run can take ~60 minutes; cached runs finish in ~5 minutes.
- CI toolchain: clang plus libev, pcre2, c-ares, openssl, libbsd, autotools. Tests run with `SKIP_BAD_REQUEST_TEST=1`.
- Local smoke test: run `./test-sanitizer-build.sh` to validate the configure flags and conflict detection without installing every dependency.

## Available Sanitizers

### AddressSanitizer (ASAN)
Detects:
- Use-after-free
- Heap/stack/global buffer overflow
- Use-after-return/scope
- Memory leaks
- Invalid pointer dereferences

### MemorySanitizer (MSAN)
Detects:
- Use of uninitialized memory
- Reading uninitialized variables
Note: requires all code (including libraries) to be built with MSAN instrumentation.

### UndefinedBehaviorSanitizer (UBSAN)
Detects:
- Integer overflow and invalid shifts
- Division by zero
- Null pointer dereference and misaligned pointer access
- Many other undefined behaviors

### ThreadSanitizer (TSAN)
Detects:
- Data races and deadlocks
- Use of destroyed mutexes
Note: TSAN cannot be used simultaneously with ASAN or MSAN.

## Local Development Usage

Use `clang` for best sanitizer support.

### Quick Start with AddressSanitizer

```bash
./autogen.sh
./configure --enable-asan
make -j$(nproc)
make check
```

### UndefinedBehaviorSanitizer

```bash
./configure --enable-ubsan
make -j$(nproc)
make check
```

### Combined ASAN + UBSAN (Recommended)

```bash
./configure --enable-asan --enable-ubsan
make -j$(nproc)
make check
```

### ThreadSanitizer

```bash
./configure --enable-tsan
make -j$(nproc)
make check
```

### MemorySanitizer (Advanced)

MSAN needs instrumented versions of all dependencies (libc++/libc++abi, libmd, libev, PCRE2, c-ares, LibreSSL, libbsd).

```bash
./configure --enable-msan
make -j$(nproc)
make check
```

For local use, build instrumented libraries and point `PKG_CONFIG_PATH`, `CFLAGS`, `CXXFLAGS`, and `LDFLAGS` at them as shown in `.github/workflows/sanitizers.yml`. Expect the first build of the instrumented toolchain to take about an hour; reuse the same prefix to avoid rebuilding.

## CI/CD Usage

- Workflow: `.github/workflows/sanitizers.yml`
- Triggers: every push and pull request
- Jobs:
  - **AddressSanitizer**: `./configure --enable-asan`
  - **UndefinedBehaviorSanitizer**: `./configure --enable-ubsan`
  - **ASAN+UBSAN**: `./configure --enable-asan --enable-ubsan`
  - **MemorySanitizer**: fully enabled; builds and caches instrumented dependencies, then configures with MSAN flags
- Each job builds with `make -j$(nproc)` and runs `make check`, uploading `tests/*.log` on failure.

MSAN caching: the cache key includes the workflow file; the first run compiles all instrumented libraries (~60 minutes), while cache hits finish in ~5 minutes.

## Environment Variables

### AddressSanitizer Options

```bash
export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:strict_init_order=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=2:strict_string_checks=1"
```

### UndefinedBehaviorSanitizer Options

```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
```

### ThreadSanitizer Options

```bash
export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"
```

### MemorySanitizer Options

```bash
export MSAN_OPTIONS="halt_on_error=1:print_stats=1:exitcode=1"
```

## Manual Builds (Without configure flags)

If you prefer to manually specify flags:

### AddressSanitizer

```bash
CC=clang \
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" \
./configure --disable-hardening

make -j$(nproc)
make check
```

### UndefinedBehaviorSanitizer

```bash
CC=clang \
CFLAGS="-fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=undefined" \
./configure --disable-hardening

make -j$(nproc)
make check
```

### ThreadSanitizer

```bash
CC=clang \
CFLAGS="-fsanitize=thread -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=thread" \
./configure --disable-hardening

make -j$(nproc)
make check
```

## Interpreting Results

### No Errors
If the tests pass without any sanitizer output, the code is clean!

### AddressSanitizer Error Example
```
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
    #0 0x... in function_name src/file.c:123
    #1 0x... in caller src/file.c:456
```

This indicates memory was accessed after being freed. The stack trace shows where the access occurred.

### UndefinedBehaviorSanitizer Error Example
```
src/file.c:123:45: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
```

This indicates undefined behavior - in this case, integer overflow.

### MemorySanitizer Error Example
```
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x... in function_name src/file.c:123
```

This indicates a variable was read before being initialized.

## Best Practices

1. Run sanitizers regularly (CI already does)
2. Fix issues immediately to avoid regressions
3. Combine ASAN + UBSAN for broad coverage
4. Use TSAN for concurrency testing
5. Test with realistic workloads so sanitizers exercise real code paths
6. Minimize false positives; use suppression files only after investigation

## Performance Impact

Sanitizers add runtime overhead:
- **ASAN**: ~2x slowdown, 2-3x memory usage
- **UBSAN**: ~20% slowdown
- **TSAN**: ~5-15x slowdown, 5-10x memory usage
- **MSAN**: ~3x slowdown, ~2x memory usage

For CI/CD, this is acceptable. For production, build without sanitizers.

## Troubleshooting

### Sanitizer library not found

```bash
# Install sanitizer libraries (Ubuntu/Debian)
sudo apt-get install libasan6 libubsan1 libtsan0

# Or use clang which bundles them
CC=clang ./configure --enable-asan
```

### Conflicts with hardening flags
Hardening flags are disabled automatically when sanitizers are enabled. You should see `Disabling hardening flags` in the configure output.

### Incompatible sanitizer combination
ASAN/MSAN/TSAN are mutually exclusive; configure aborts with `Cannot enable multiple memory sanitizers (ASAN/MSAN/TSAN) simultaneously` if you try to combine them.

### Tests fail with sanitizers but pass normally
This is expected—sanitizers reveal bugs that don't always cause immediate failures. Investigate and fix the issues.

## References

- [AddressSanitizer Documentation](https://clang.llvm.org/docs/AddressSanitizer.html)
- [MemorySanitizer Documentation](https://clang.llvm.org/docs/MemorySanitizer.html)
- [UndefinedBehaviorSanitizer Documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [ThreadSanitizer Documentation](https://clang.llvm.org/docs/ThreadSanitizer.html)
- [Google Sanitizers Wiki](https://github.com/google/sanitizers/wiki)
