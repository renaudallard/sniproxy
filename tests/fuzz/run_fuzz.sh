#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/tests/fuzz/bin"}
CORPUS_ROOT=${CORPUS_ROOT:-"$ROOT_DIR/tests/fuzz/corpus"}
FUZZ_CC=${FUZZ_CC:-clang}
FUZZ_OPTIONAL=${FUZZ_OPTIONAL:-1}
FUZZ_RUNTIME=${FUZZ_RUNTIME:-30}
FUZZ_VERBOSE=${FUZZ_VERBOSE:-1}
EXTRA_FLAGS=${FUZZ_CFLAGS:-"-O1 -g"}
COMMON_FLAGS=("-fsanitize=fuzzer,address,undefined" "-fno-omit-frame-pointer" "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" "-DHAVE_CONFIG_H" "-DHAVE_LIBPCRE2_8" "-I$ROOT_DIR" "-I$ROOT_DIR/src")

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcre2-8; then
    : "${PCRE2_CFLAGS:=$(pkg-config --cflags libpcre2-8)}"
    : "${PCRE2_LIBS:=$(pkg-config --libs libpcre2-8)}"
else
    : "${PCRE2_CFLAGS:=}"
    : "${PCRE2_LIBS:=-lpcre2-8}"
fi

if [[ -n "$PCRE2_CFLAGS" ]]; then
    COMMON_FLAGS+=("$PCRE2_CFLAGS")
fi

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

mkdir -p "$OUT_DIR" \
    "$CORPUS_ROOT/tls" \
    "$CORPUS_ROOT/http2" \
    "$CORPUS_ROOT/http" \
    "$CORPUS_ROOT/hostname" \
    "$CORPUS_ROOT/cfg_tokenizer" \
    "$CORPUS_ROOT/ipc_crypto" \
    "$CORPUS_ROOT/ipc_msg" \
    "$CORPUS_ROOT/address" \
    "$CORPUS_ROOT/table_lookup" \
    "$CORPUS_ROOT/listener_acl" \
    "$CORPUS_ROOT/config" \
    "$CORPUS_ROOT/ipc_state" \
    "$CORPUS_ROOT/resolver_response"

vlog() {
    if [[ "${FUZZ_VERBOSE}" -ne 0 ]]; then
        printf '%s\n' "$*"
    fi
}

run_with_optional_quiet() {
    if [[ "${FUZZ_VERBOSE}" -ne 0 ]]; then
        "$@"
    else
        "$@" >/dev/null
    fi
}

build_fuzzer() {
    local target=$1
    shift
    if [[ "${FUZZ_VERBOSE}" -ne 0 ]]; then
        "$FUZZ_CC" $EXTRA_FLAGS "${COMMON_FLAGS[@]}" "$@" $PCRE2_LIBS -o "$OUT_DIR/$target"
    else
        "$FUZZ_CC" $EXTRA_FLAGS "${COMMON_FLAGS[@]}" "$@" $PCRE2_LIBS -o "$OUT_DIR/$target" >/dev/null
    fi
}

vlog "Building fuzzers..."

build_fuzzer ipc_msg_fuzz \
    "$ROOT_DIR/tests/fuzz/ipc_msg_fuzz.c" \
    "$ROOT_DIR/src/ipc_crypto.c" \
    -lcrypto

build_fuzzer ipc_crypto_fuzz \
    "$ROOT_DIR/tests/fuzz/ipc_crypto_fuzz.c" \
    "$ROOT_DIR/src/ipc_crypto.c" \
    -lcrypto

build_fuzzer ipc_state_fuzz \
    "$ROOT_DIR/tests/fuzz/ipc_state_fuzz.c" \
    "$ROOT_DIR/src/ipc_crypto.c" \
    -lcrypto

build_fuzzer address_fuzz \
    "$ROOT_DIR/tests/fuzz/address_fuzz.c" \
    "$ROOT_DIR/src/address.c"

build_fuzzer table_lookup_fuzz \
    "$ROOT_DIR/tests/fuzz/table_lookup_fuzz.c" \
    "$ROOT_DIR/src/address.c" \
    "$ROOT_DIR/src/backend.c" \
    "$ROOT_DIR/src/table.c"

build_fuzzer listener_acl_fuzz \
    "$ROOT_DIR/tests/fuzz/listener_acl_fuzz.c" \
    "$ROOT_DIR/src/listener.c" \
    "$ROOT_DIR/src/address.c" \
    "$ROOT_DIR/src/backend.c" \
    "$ROOT_DIR/src/table.c" \
    -I"$ROOT_DIR/tests/include"

build_fuzzer resolver_response_fuzz \
    "$ROOT_DIR/tests/fuzz/resolver_response_fuzz.c" \
    "$ROOT_DIR/src/address.c" \
    "$ROOT_DIR/src/ipc_crypto.c" \
    "$ROOT_DIR/src/resolv.c" \
    -I"$ROOT_DIR/tests/include" \
    -lev -lssl -lcrypto -lcares

build_fuzzer config_fuzz \
    "$ROOT_DIR/tests/fuzz/config_fuzz.c" \
    "$ROOT_DIR/src/binder.c" \
    "$ROOT_DIR/src/config.c" \
    "$ROOT_DIR/src/cfg_parser.c" \
    "$ROOT_DIR/src/cfg_tokenizer.c" \
    "$ROOT_DIR/src/address.c" \
    "$ROOT_DIR/src/backend.c" \
    "$ROOT_DIR/src/table.c" \
    "$ROOT_DIR/src/listener.c" \
    "$ROOT_DIR/src/connection.c" \
    "$ROOT_DIR/src/buffer.c" \
    "$ROOT_DIR/src/logger.c" \
    "$ROOT_DIR/src/ipc_crypto.c" \
    "$ROOT_DIR/src/resolv.c" \
    "$ROOT_DIR/src/tls.c" \
    "$ROOT_DIR/src/http.c" \
    "$ROOT_DIR/src/http2.c" \
    "$ROOT_DIR/src/http2_huffman.c" \
    -lev -lssl -lcrypto -lcares

build_fuzzer http2_fuzz \
    "$ROOT_DIR/tests/fuzz/http2_fuzz.c" \
    "$ROOT_DIR/src/http2.c" \
    "$ROOT_DIR/src/http2_huffman.c"

build_fuzzer http_fuzz \
    "$ROOT_DIR/tests/fuzz/http_fuzz.c" \
    "$ROOT_DIR/src/http.c" \
    "$ROOT_DIR/src/http2.c" \
    "$ROOT_DIR/src/http2_huffman.c"

build_fuzzer hostname_fuzz \
    "$ROOT_DIR/tests/fuzz/hostname_fuzz.c"

build_fuzzer cfg_tokenizer_fuzz \
    "$ROOT_DIR/tests/fuzz/cfg_tokenizer_fuzz.c" \
    "$ROOT_DIR/src/cfg_tokenizer.c"

build_fuzzer tls_fuzz \
    "$ROOT_DIR/tests/fuzz/tls_fuzz.c" \
    "$ROOT_DIR/src/tls.c"

vlog "Fuzzers built successfully."

if [[ ${RUN_FUZZ:-1} -eq 0 ]]; then
    exit 0
fi

vlog "Running fuzzers for ${FUZZ_RUNTIME}s each..."

run_with_optional_quiet "$OUT_DIR/ipc_msg_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/ipc_msg"
run_with_optional_quiet "$OUT_DIR/ipc_crypto_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/ipc_crypto"
run_with_optional_quiet "$OUT_DIR/ipc_state_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/ipc_state"
run_with_optional_quiet "$OUT_DIR/address_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/address"
run_with_optional_quiet "$OUT_DIR/table_lookup_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/table_lookup"
run_with_optional_quiet "$OUT_DIR/listener_acl_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/listener_acl"
run_with_optional_quiet "$OUT_DIR/resolver_response_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/resolver_response"
run_with_optional_quiet "$OUT_DIR/config_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/config"
run_with_optional_quiet "$OUT_DIR/http2_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/http2"
run_with_optional_quiet "$OUT_DIR/http_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/http"
run_with_optional_quiet "$OUT_DIR/hostname_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/hostname"
run_with_optional_quiet "$OUT_DIR/cfg_tokenizer_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/cfg_tokenizer"
run_with_optional_quiet "$OUT_DIR/tls_fuzz" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/tls"

vlog "Fuzzing complete. No crashes detected."
