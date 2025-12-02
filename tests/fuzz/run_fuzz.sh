#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/tests/fuzz/bin"}
CORPUS_ROOT=${CORPUS_ROOT:-"$ROOT_DIR/tests/fuzz/corpus"}
FUZZ_CC=${FUZZ_CC:-clang}
FUZZ_OPTIONAL=${FUZZ_OPTIONAL:-1}
FUZZ_RUNTIME=${FUZZ_RUNTIME:-30}
FUZZ_VERBOSE=${FUZZ_VERBOSE:-1}
FUZZ_PARALLEL=${FUZZ_PARALLEL:-0}
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

LIBBSD_CFLAGS=""
LIBBSD_LIBS=""
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbsd; then
    LIBBSD_CFLAGS=$(pkg-config --cflags libbsd)
    LIBBSD_LIBS=$(pkg-config --libs libbsd)
fi
if [[ -n "$LIBBSD_CFLAGS" ]]; then
    COMMON_FLAGS+=("$LIBBSD_CFLAGS" "-DHAVE_ARC4RANDOM" "-DHAVE_BSD_STDLIB_H")
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
        "$FUZZ_CC" $EXTRA_FLAGS "${COMMON_FLAGS[@]}" "$@" $PCRE2_LIBS $LIBBSD_LIBS -o "$OUT_DIR/$target"
    else
        "$FUZZ_CC" $EXTRA_FLAGS "${COMMON_FLAGS[@]}" "$@" $PCRE2_LIBS $LIBBSD_LIBS -o "$OUT_DIR/$target" >/dev/null
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
    "$ROOT_DIR/src/seccomp.c" \
    -I"$ROOT_DIR/tests/include" \
    -lev -lssl -lcrypto -lcares -lseccomp

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
    "$ROOT_DIR/src/seccomp.c" \
    -lev -lssl -lcrypto -lcares -lseccomp

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

# Define all fuzz targets
FUZZ_TARGETS=(
    "ipc_msg_fuzz:ipc_msg"
    "ipc_crypto_fuzz:ipc_crypto"
    "ipc_state_fuzz:ipc_state"
    "address_fuzz:address"
    "table_lookup_fuzz:table_lookup"
    "listener_acl_fuzz:listener_acl"
    "resolver_response_fuzz:resolver_response"
    "config_fuzz:config"
    "http2_fuzz:http2"
    "http_fuzz:http"
    "hostname_fuzz:hostname"
    "cfg_tokenizer_fuzz:cfg_tokenizer"
    "tls_fuzz:tls"
)

run_single_fuzzer() {
    local fuzzer=$1
    local corpus=$2
    local log_file="$OUT_DIR/${fuzzer}.log"

    if [[ "${FUZZ_VERBOSE}" -ne 0 ]]; then
        "$OUT_DIR/$fuzzer" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/$corpus" 2>&1 | tee "$log_file"
    else
        "$OUT_DIR/$fuzzer" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/$corpus" >"$log_file" 2>&1
    fi

    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "error: $fuzzer exited with code $exit_code" >&2
        if [[ "${FUZZ_VERBOSE}" -eq 0 ]]; then
            echo "Last 50 lines of $fuzzer output:" >&2
            tail -n 50 "$log_file" >&2 || true
        fi
    fi
    return $exit_code
}

if [[ "${FUZZ_PARALLEL}" -ne 0 ]]; then
    vlog "Running ${#FUZZ_TARGETS[@]} fuzzers in parallel for ${FUZZ_RUNTIME}s each..."

    pids=()
    failed_fuzzers=()

    # Start all fuzzers in background
    for target in "${FUZZ_TARGETS[@]}"; do
        IFS=':' read -r fuzzer corpus <<< "$target"
        run_single_fuzzer "$fuzzer" "$corpus" &
        pids+=($!)
    done

    # Wait for all fuzzers and collect exit codes
    overall_status=0
    for i in "${!pids[@]}"; do
        IFS=':' read -r fuzzer corpus <<< "${FUZZ_TARGETS[$i]}"
        if ! wait "${pids[$i]}"; then
            failed_fuzzers+=("$fuzzer")
            overall_status=1
        fi
    done

    if [[ $overall_status -ne 0 ]]; then
        echo "error: The following fuzzers failed: ${failed_fuzzers[*]}" >&2
        exit 1
    fi

    vlog "Parallel fuzzing complete. No crashes detected."
else
    vlog "Running fuzzers sequentially for ${FUZZ_RUNTIME}s each..."

    for target in "${FUZZ_TARGETS[@]}"; do
        IFS=':' read -r fuzzer corpus <<< "$target"
        run_with_optional_quiet "$OUT_DIR/$fuzzer" -max_total_time=$FUZZ_RUNTIME "$CORPUS_ROOT/$corpus"
    done

    vlog "Fuzzing complete. No crashes detected."
fi
