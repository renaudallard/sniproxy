#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "ipc_crypto.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define PACKAGE_NAME "sniproxy"
#endif

struct Logger;

/* Minimal logger stubs */
static void swallow_log(const char *fmt __attribute__((unused)),
                        va_list ap __attribute__((unused))) {}

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
    abort();
}

void err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void notice(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    swallow_log(fmt, ap);
    va_end(ap);
}

void log_msg(struct Logger *logger __attribute__((unused)),
             int priority __attribute__((unused)),
             const char *fmt __attribute__((unused)), ...) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct ipc_crypto_state state;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    /* Limit size to avoid excessive memory usage */
    if (size == 0 || size > 65536)
        return 0;

    /* Initialize crypto system once */
    static int initialized = 0;
    if (!initialized) {
        if (ipc_crypto_system_init() < 0)
            return 0;
        initialized = 1;
    }

    /* Initialize a crypto state */
    if (ipc_crypto_channel_init(&state, 0x54455354u /* 'TEST' */,
                                IPC_CRYPTO_ROLE_PARENT) < 0)
        return 0;

    /* Test 1: Try to decrypt arbitrary data as if it were an encrypted frame */
    size_t max_payload = 4096;
    ipc_crypto_open(&state, data, size, max_payload, &plaintext, &plaintext_len);
    free(plaintext);
    plaintext = NULL;

    /* Test 2: Encrypt the fuzzer input and then decrypt it (round-trip).
     * Use a child state for decryption since parent and child have
     * matching send/recv keys (parent sends with P2C, child receives
     * with P2C). */
    struct ipc_crypto_state child_state;
    if (ipc_crypto_channel_init(&child_state, 0x54455354u /* 'TEST' */,
                                IPC_CRYPTO_ROLE_CHILD) == 0) {
        uint8_t *frame = NULL;
        size_t frame_len = 0;

        if (ipc_crypto_seal(&state, data, size, &frame, &frame_len) == 0) {
            if (ipc_crypto_open(&child_state, frame, frame_len, size,
                               &plaintext, &plaintext_len) == 0) {
                /* Verify round-trip integrity */
                if (plaintext_len == size &&
                    memcmp(plaintext, data, size) != 0) {
                    abort();
                }
            }
            free(plaintext);
            free(frame);
        }
        ipc_crypto_state_clear(&child_state);
    }

    /* Clean up */
    ipc_crypto_state_clear(&state);
    return 0;
}
