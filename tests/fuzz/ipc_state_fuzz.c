#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include "ipc_crypto.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define PACKAGE_NAME "sniproxy"
#endif

struct Logger;

/* Minimal logger stubs to satisfy linker dependencies */
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

static int
ensure_crypto_init(void) {
    static int initialized = 0;
    if (!initialized) {
        if (ipc_crypto_system_init() < 0)
            return 0;
        initialized = 1;
    }
    return 1;
}

static size_t
consume_len(const uint8_t **data, size_t *remaining, size_t max) {
    if (*remaining == 0)
        return 0;
    size_t len = (size_t)((**data) % (max + 1));
    (*data)++;
    (*remaining)--;
    if (len > *remaining)
        len = *remaining;
    return len;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0)
        return 0;

    if (!ensure_crypto_init())
        return 0;

    struct ipc_crypto_state state;
    int state_ready = 0;
    uint8_t *last_frame = NULL;
    size_t last_frame_len = 0;

    const uint8_t *ptr = data;
    size_t remaining = size;

    while (remaining > 0) {
        uint8_t op = *ptr++;
        remaining--;

        switch (op % 8) {
        case 0: /* init parent */
            if (state_ready)
                ipc_crypto_state_clear(&state);
            if (ipc_crypto_channel_init(&state, 0x434c5041u, IPC_CRYPTO_ROLE_PARENT) == 0)
                state_ready = 1;
            break;
        case 1: /* init child */
            if (state_ready)
                ipc_crypto_state_clear(&state);
            if (ipc_crypto_channel_init(&state, 0x434c5042u, IPC_CRYPTO_ROLE_CHILD) == 0)
                state_ready = 1;
            break;
        case 2: /* change role */
            if (state_ready) {
                enum ipc_crypto_role role = (op & 0x1) ? IPC_CRYPTO_ROLE_PARENT : IPC_CRYPTO_ROLE_CHILD;
                (void)ipc_crypto_channel_set_role(&state, role);
            }
            break;
        case 3: /* seal random chunk */
            if (state_ready && remaining > 0) {
                size_t chunk_len = consume_len(&ptr, &remaining, 2048);
                uint8_t *plaintext = NULL;
                if (chunk_len > 0) {
                    plaintext = malloc(chunk_len);
                    if (plaintext == NULL)
                        break;
                    memcpy(plaintext, ptr, chunk_len);
                    ptr += chunk_len;
                    remaining -= chunk_len;
                }

                uint8_t *frame = NULL;
                size_t frame_len = 0;
                if (ipc_crypto_seal(&state, plaintext, chunk_len, &frame, &frame_len) == 0) {
                    free(last_frame);
                    last_frame = frame;
                    last_frame_len = frame_len;
                } else {
                    free(frame);
                }
                free(plaintext);
            }
            break;
        case 4: /* attempt decrypt random data */
            if (state_ready) {
                size_t blob_len = consume_len(&ptr, &remaining, 2048);
                const uint8_t *blob = ptr;
                if (blob_len > remaining)
                    blob_len = remaining;
                ptr += blob_len;
                remaining -= blob_len;

                uint8_t *plaintext = NULL;
                size_t plaintext_len = 0;
                ipc_crypto_open(&state, blob, blob_len, 4096, &plaintext, &plaintext_len);
                free(plaintext);
            }
            break;
        case 5: /* decrypt last frame if any */
            if (state_ready && last_frame != NULL) {
                uint8_t *plaintext = NULL;
                size_t plaintext_len = 0;
                ipc_crypto_open(&state, last_frame, last_frame_len, 4096, &plaintext,
                        &plaintext_len);
                if (plaintext_len > 0 && plaintext != NULL)
                    plaintext[0] = (uint8_t)(plaintext[0] ^ op);
                free(plaintext);
            }
            break;
        case 6: /* force counters near wrap */
            if (state_ready) {
                state.send_counter = UINT64_MAX - (op & 0x0f);
                state.recv_counter = UINT64_MAX - ((op >> 4) & 0x0f);
                state.send_key_timestamp = 0;
                state.recv_key_timestamp = 0;
            }
            break;
        case 7: /* clear state */
            if (state_ready) {
                ipc_crypto_state_clear(&state);
                state_ready = 0;
            }
            break;
        }
    }

    if (state_ready)
        ipc_crypto_state_clear(&state);
    free(last_frame);

    return 0;
}
