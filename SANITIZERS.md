# Memory Sanitizers Guide

This document explains how to use AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer with sniproxy.

## Overview

Memory sanitizers are runtime error detection tools that help identify memory bugs, undefined behavior, and concurrency issues. They are invaluable for finding subtle bugs that might not cause immediate crashes but can lead to security vulnerabilities or data corruption.

## Available Sanitizers

### AddressSanitizer (ASAN)
Detects:
- Use-after-free
- Heap buffer overflow
- Stack buffer overflow
- Global buffer overflow
- Use-after-return
- Use-after-scope
- Memory leaks
- Invalid pointer dereferences

### MemorySanitizer (MSAN)
Detects:
- Use of uninitialized memory
- Reading uninitialized variables

**Note:** MSan requires all code (including libraries) to be built with MSan instrumentation.

### UndefinedBehaviorSanitizer (UBSAN)
Detects:
- Integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointer access
- Signed integer overflow
- Invalid shifts
- And many other undefined behaviors

### ThreadSanitizer (TSAN)
Detects:
- Data races
- Deadlocks
- Use of destroyed mutexes

**Note:** TSAN cannot be used simultaneously with ASAN or MSAN.

## Local Development Usage

### Quick Start with AddressSanitizer

```bash
# Generate build system
./autogen.sh

# Configure with ASAN
./configure --enable-asan

# Build and test
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

You can combine ASAN and UBSAN for comprehensive coverage:

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

MSan requires instrumented versions of ALL libraries (libc++, libev, libpcre2, c-ares, OpenSSL, libbsd).

**Good news:** The GitHub Actions workflow builds and caches all instrumented libraries automatically!

**For local use:**
```bash
# Use the --enable-msan flag (but you'll need instrumented libraries)
./configure --enable-msan
make -j$(nproc)
make check
```

**Note:** Local MSAN testing requires building instrumented versions of all dependencies.
See the CI workflow `.github/workflows/sanitizers.yml` for the complete build process.
The workflow caches the instrumented libraries, so the first run takes ~60 minutes,
but subsequent runs use cached libraries and complete in ~5 minutes.

## CI/CD Usage

### GitHub Actions

The project includes a comprehensive sanitizer workflow in `.github/workflows/sanitizers.yml` that automatically runs:

1. **AddressSanitizer** - Detects memory errors
2. **UndefinedBehaviorSanitizer** - Detects undefined behavior
3. **Combined ASAN+UBSAN** - Both sanitizers together
4. **MemorySanitizer** - Notes on setup (disabled by default due to complexity)

The workflow runs automatically on:
- Every push to any branch
- Every pull request

**MSAN Caching:** The first MSAN run builds all instrumented libraries (~60 minutes).
Subsequent runs use cached libraries and complete in ~5 minutes. Cache is invalidated
when the workflow file changes.

### Environment Variables

Sanitizers can be configured via environment variables:

#### AddressSanitizer Options
```bash
export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:strict_init_order=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=2:strict_string_checks=1"
```

#### UndefinedBehaviorSanitizer Options
```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
```

#### ThreadSanitizer Options
```bash
export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"
```

#### MemorySanitizer Options
```bash
export MSAN_OPTIONS="halt_on_error=1:print_stats=1"
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

1. **Run sanitizers regularly** - Include them in your CI/CD pipeline
2. **Fix issues immediately** - Don't let sanitizer errors accumulate
3. **Combine ASAN + UBSAN** - They complement each other well
4. **Use TSAN for concurrency** - Essential for multi-threaded code
5. **Test with realistic workloads** - Sanitizers only detect issues in code that actually runs
6. **Minimize false positives** - Use suppression files if needed (but investigate first!)

## Performance Impact

Sanitizers add runtime overhead:
- **ASAN**: ~2x slowdown, 2-3x memory usage
- **UBSAN**: ~20% slowdown
- **TSAN**: ~5-15x slowdown, 5-10x memory usage
- **MSAN**: ~3x slowdown

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
The configure script automatically disables hardening flags when sanitizers are enabled, as some flags conflict.

### Tests fail with sanitizers but pass normally
This is expected! Sanitizers reveal bugs that don't always cause immediate failures. Investigate and fix the issues.

## References

- [AddressSanitizer Documentation](https://clang.llvm.org/docs/AddressSanitizer.html)
- [MemorySanitizer Documentation](https://clang.llvm.org/docs/MemorySanitizer.html)
- [UndefinedBehaviorSanitizer Documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [ThreadSanitizer Documentation](https://clang.llvm.org/docs/ThreadSanitizer.html)
- [Google Sanitizers Wiki](https://github.com/google/sanitizers/wiki)
