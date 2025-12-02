# Sanitizer Workflow Testing Checklist

This checklist verifies that the sanitizer CI/CD workflow is ready to run.

## Pre-Flight Checks

### Build System Integration
- [x] configure.ac has --enable-asan, --enable-msan, --enable-ubsan, --enable-tsan flags
- [x] SANITIZER_CFLAGS and SANITIZER_LDFLAGS variables defined
- [x] Conflict detection prevents mixing ASAN/MSAN/TSAN
- [x] Hardening flags auto-disabled when sanitizers enabled
- [x] src/Makefile.am uses $(SANITIZER_CFLAGS) and $(SANITIZER_LDFLAGS)
- [x] tests/Makefile.am uses $(SANITIZER_CFLAGS) and $(SANITIZER_LDFLAGS)

### Workflow Configuration
- [x] .github/workflows/sanitizers.yml created
- [x] All required dependencies listed (libev-dev, libpcre2-dev, libc-ares-dev, libssl-dev, libbsd-dev)
- [x] Uses CC=clang for best sanitizer support
- [x] Uses --enable-asan configure flag (not manual CFLAGS)
- [x] Uses --enable-ubsan configure flag
- [x] Combined job uses --enable-asan --enable-ubsan
- [x] Proper ASAN_OPTIONS set for leak detection
- [x] Proper UBSAN_OPTIONS set for stack traces
- [x] Test logs uploaded on failure
- [x] SKIP_BAD_REQUEST_TEST=1 set (same as other workflows)

### Jobs Defined
- [x] address-sanitizer - Tests with ASAN
- [x] undefined-behavior-sanitizer - Tests with UBSAN
- [x] combined-sanitizers - Tests with ASAN+UBSAN together
- [x] memory-sanitizer - Runs MSAN using instrumented dependencies and cache

### Documentation
- [x] SANITIZERS.md created with comprehensive guide
- [x] README.md updated to reference sanitizers
- [x] Local development instructions included
- [x] CI/CD usage documented
- [x] Environment variables documented
- [x] Troubleshooting section included

## What Gets Tested

When the workflow runs, it will:

1. **AddressSanitizer Job**
   - Detects: use-after-free, heap/stack/global buffer overflows, memory leaks
   - Configuration: ASAN with leak detection enabled
   - Expected: All tests pass with no ASAN errors

2. **UndefinedBehaviorSanitizer Job**
   - Detects: integer overflow, division by zero, null dereference, invalid shifts
   - Configuration: UBSAN with halt-on-error
   - Expected: All tests pass with no undefined behavior

3. **Combined ASAN+UBSAN Job** (Most Important)
   - Detects: Both memory errors AND undefined behavior
   - Configuration: Both sanitizers together
   - Expected: All tests pass with no errors from either sanitizer

4. **MemorySanitizer Job**
   - Detects: use of uninitialized memory
   - Status: Active; builds and caches instrumented dependencies (libc++/libc++abi, libmd, libev, PCRE2, c-ares, LibreSSL, libbsd)
   - Timing: First run ~60 minutes to build toolchain; cached runs ~5 minutes

## Expected Output

### Successful Run
```
✓ Configure with AddressSanitizer
✓ Build
✓ Run tests with ASAN
  All tests passed
```

### If Sanitizer Finds Issues
```
==12345==ERROR: AddressSanitizer: heap-use-after-free
    #0 0x... in function_name src/file.c:123
```
This is GOOD - it means the sanitizers are working and found a real bug that needs fixing!

## Local Testing

Before pushing, developers can test locally:

```bash
./autogen.sh
CC=clang ./configure --enable-asan --enable-ubsan
make -j$(nproc)
make check
```

## Maintenance Notes

- The workflow runs on every push and pull request
- Failed sanitizer runs should be investigated immediately
- Sanitizer findings often indicate real security vulnerabilities
- Keep ASAN_OPTIONS and UBSAN_OPTIONS aligned with best practices
- Update libbsd-dev if arc4random issues appear

## Known Limitations

- MSAN cold-cache runs are slow because instrumented dependencies are rebuilt
- TSAN may have false positives with some libraries
- Sanitizers add ~2-5x runtime overhead (acceptable for CI)
- Some tests may need suppressions for third-party library issues

## Next Steps After Merging

1. Monitor first few CI runs for any issues
2. Fix any sanitizer findings that appear
3. Consider adding TSAN in a separate job for threading tests
4. Keep an eye on MSAN cache hit rate; if cache churn is high, pin versions or adjust keys

---

**Status**: Ready for production use ✓

All sanitizers are properly configured and ready to catch memory bugs and undefined behavior in CI/CD!
