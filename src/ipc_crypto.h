/*
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef IPC_CRYPTO_H
#define IPC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

enum ipc_crypto_role {
    IPC_CRYPTO_ROLE_PARENT = 0,
    IPC_CRYPTO_ROLE_CHILD = 1,
};

#define IPC_CRYPTO_NONCE_LEN 12
#define IPC_CRYPTO_TAG_LEN 16
#define IPC_CRYPTO_HEADER_LEN (sizeof(uint32_t) * 2 + IPC_CRYPTO_NONCE_LEN)
#define IPC_CRYPTO_OVERHEAD (IPC_CRYPTO_HEADER_LEN + IPC_CRYPTO_TAG_LEN)
#define IPC_CRYPTO_MAX_FRAME(payload_max) \
    (IPC_CRYPTO_HEADER_LEN + (payload_max) + IPC_CRYPTO_TAG_LEN)
#define IPC_CRYPTO_MAGIC 0x49504331u /* 'IPC1' */

struct ipc_crypto_state {
    uint32_t channel_id;
    uint8_t base_key[32];
    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint64_t send_counter;
    enum ipc_crypto_role role;
};

int ipc_crypto_system_init(void);
int ipc_crypto_channel_init(struct ipc_crypto_state *state, uint32_t channel_id,
        enum ipc_crypto_role role);
int ipc_crypto_channel_set_role(struct ipc_crypto_state *state,
        enum ipc_crypto_role role);
int ipc_crypto_seal(struct ipc_crypto_state *state, const uint8_t *plaintext,
        size_t plaintext_len, uint8_t **frame, size_t *frame_len);
int ipc_crypto_open(struct ipc_crypto_state *state, const uint8_t *frame,
        size_t frame_len, uint8_t **plaintext, size_t *plaintext_len);
int ipc_crypto_send_msg(struct ipc_crypto_state *state, int sockfd,
        const void *payload, size_t payload_len, int fd_to_send);
int ipc_crypto_recv_msg(struct ipc_crypto_state *state, int sockfd,
        size_t max_payload_len, uint8_t **plaintext, size_t *plaintext_len,
        int *received_fd);
void ipc_crypto_state_clear(struct ipc_crypto_state *state);

#endif /* IPC_CRYPTO_H */
