#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/tests/fuzz/bin"}
CORPUS_ROOT=${CORPUS_ROOT:-"$ROOT_DIR/tests/fuzz/corpus"}
FUZZ_CC=${FUZZ_CC:-clang}
FUZZ_OPTIONAL=${FUZZ_OPTIONAL:-1}
FUZZ_RUNTIME=${FUZZ_RUNTIME:-30}
EXTRA_FLAGS=${FUZZ_CFLAGS:-"-O1 -g"}
COMMON_FLAGS=("-fsanitize=fuzzer,address,undefined" "-fno-omit-frame-pointer" "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" "-DHAVE_CONFIG_H" "-I$ROOT_DIR" "-I$ROOT_DIR/src")

if ! command -v "$FUZZ_CC" >/dev/null 2>&1; then
    echo "error: $FUZZ_CC is required for libFuzzer builds" >&2
    exit 1
fi

check_fuzzer_support() {
    local tmp_src tmp_bin tmp_log
    tmp_src=$(mktemp ${TMPDIR:-/tmp}/sniproxy-fuzz-XXXXXX.c)
    tmp_bin="${tmp_src%.c}"
    tmp_log=$(mktemp ${TMPDIR:-/tmp}/sniproxy-fuzz-XXXXXX.log)
    cat <<'SRC' > "$tmp_src"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}
SRC
    if "$FUZZ_CC" -fsanitize=fuzzer "$tmp_src" -o "$tmp_bin" >/dev/null 2>"$tmp_log"; then
        rm -f "$tmp_src" "$tmp_bin" "$tmp_log"
        return 0
    fi
    echo "compiler output from $FUZZ_CC -fsanitize=fuzzer:" >&2
    cat "$tmp_log" >&2 || true
    rm -f "$tmp_src" "$tmp_bin" "$tmp_log"
    return 1
}

if ! check_fuzzer_support; then
    if [[ $FUZZ_OPTIONAL -ne 0 ]]; then
        echo "warning: libFuzzer not supported by $FUZZ_CC, skipping fuzz build" >&2
        exit 0
    fi
    echo "error: libFuzzer is required but not available in $FUZZ_CC" >&2
    exit 1
fi

mkdir -p "$OUT_DIR" "$CORPUS_ROOT/tls" "$CORPUS_ROOT/http2"

build_fuzzer() {
    local target=$1
    shift
    "$FUZZ_CC" $EXTRA_FLAGS "${COMMON_FLAGS[@]}" "$@" -o "$OUT_DIR/$target"
}

build_fuzzer tls_fuzz \
    "$ROOT_DIR/tests/fuzz/tls_fuzz.c" \
    "$ROOT_DIR/src/tls.c"

build_fuzzer http2_fuzz \
    "$ROOT_DIR/tests/fuzz/http2_fuzz.c" \
    "$ROOT_DIR/src/http2.c" \
    "$ROOT_DIR/src/http2_huffman.c"

if [[ ${RUN_FUZZ:-1} -eq 0 ]]; then
    exit 0
fi

"$OUT_DIR/tls_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/tls"
"$OUT_DIR/http2_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/http2"
