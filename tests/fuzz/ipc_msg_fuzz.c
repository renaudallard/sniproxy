#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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

static void
drain_socket(int fd) {
    /* Ensure socket fully drained to avoid blocking future fuzz iterations */
    uint8_t buf[128];
    while (read(fd, buf, sizeof(buf)) > 0)
        ;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0)
        return 0;

    if (size > 65536)
        size = 65536;

    if (!ensure_crypto_init())
        return 0;

    struct ipc_crypto_state sender;
    struct ipc_crypto_state receiver;

    if (ipc_crypto_channel_init(&sender, 0x4d534731u /* MSG1 */,
                IPC_CRYPTO_ROLE_PARENT) < 0)
        return 0;
    if (ipc_crypto_channel_init(&receiver, 0x4d534731u,
                IPC_CRYPTO_ROLE_CHILD) < 0) {
        ipc_crypto_state_clear(&sender);
        return 0;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        ipc_crypto_state_clear(&sender);
        ipc_crypto_state_clear(&receiver);
        return 0;
    }

    const size_t max_payload = 4096;
    size_t send_len = size;
    if (send_len > max_payload)
        send_len = max_payload;

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    int received_fd = -1;

    if (ipc_crypto_send_msg(&sender, sv[0], data, send_len, -1) == 0) {
        if (ipc_crypto_recv_msg(&receiver, sv[1], max_payload, &plaintext,
                    &plaintext_len, &received_fd) == 0) {
            if (plaintext != NULL && plaintext_len > 0)
                memset(plaintext, 0, plaintext_len);
        }
        if (received_fd >= 0)
            close(received_fd);
        free(plaintext);
        plaintext = NULL;
        plaintext_len = 0;
    } else {
        drain_socket(sv[1]);
    }

    size_t remaining = size - send_len;
    if (remaining > 0) {
        const uint8_t *frame = data + send_len;
        uint32_t net_len = htonl((uint32_t)remaining);
        (void)write(sv[0], &net_len, sizeof(net_len));
        if (remaining > 0)
            (void)write(sv[0], frame, remaining);

        received_fd = -1;
        plaintext = NULL;
        plaintext_len = 0;
        ipc_crypto_recv_msg(&receiver, sv[1], max_payload, &plaintext,
                &plaintext_len, &received_fd);
        if (received_fd >= 0)
            close(received_fd);
        free(plaintext);
    }

    close(sv[0]);
    close(sv[1]);
    ipc_crypto_state_clear(&sender);
    ipc_crypto_state_clear(&receiver);

    return 0;
}
