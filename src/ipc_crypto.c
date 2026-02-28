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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include "ipc_crypto.h"
#include "logger.h"

static uint64_t host_to_be64(uint64_t host) {
    uint32_t high = (uint32_t)(host >> 32);
    uint32_t low = (uint32_t)(host & 0xffffffffu);
    uint64_t converted = ((uint64_t)htonl(high) << 32) | htonl(low);
    return converted;
}

#define IPC_CRYPTO_LABEL_PARENT_SEND "P2C"
#define IPC_CRYPTO_LABEL_PARENT_RECV "C2P"
#define IPC_CRYPTO_LABEL_CHILD_SEND  "C2P"
#define IPC_CRYPTO_LABEL_CHILD_RECV  "P2C"

/* Rekey threshold: trigger rekey at 2^63 to stay well below counter max.
 * This provides 9.2 quintillion messages before rekey, which should be
 * sufficient for any realistic IPC workload while preventing counter
 * exhaustion and nonce reuse. */
#define IPC_CRYPTO_REKEY_THRESHOLD ((uint64_t)1 << 63)

/* Time-based rekey interval: rotate keys every week (7 days).
 * This provides defense-in-depth by limiting key lifetime even if
 * the counter threshold is never reached. */
#define IPC_CRYPTO_REKEY_INTERVAL (7 * 24 * 60 * 60)  /* 7 days in seconds */

/* Maximum allowed generation gap between sender and receiver.
 * This limits DoS attacks where an attacker sends a message with a
 * very large generation number, forcing the receiver to perform
 * billions of rekey operations. A gap of 16 allows for reasonable
 * message reordering and recovery scenarios while preventing abuse. */
#define IPC_CRYPTO_MAX_GENERATION_GAP 16

/* HKDF-SHA256 key derivation function.
 * This replaces raw SHA256 hashing with proper HKDF as per RFC 5869.
 * salt: optional salt value (can be NULL)
 * salt_len: length of salt (0 if salt is NULL)
 * ikm: input key material
 * ikm_len: length of input key material
 * info: optional context/application specific info (can be NULL)
 * info_len: length of info (0 if info is NULL)
 * out: output buffer (must be 32 bytes for SHA256)
 */
static int
hkdf_sha256(const uint8_t *salt, size_t salt_len,
        const uint8_t *ikm, size_t ikm_len,
        const uint8_t *info, size_t info_len,
        uint8_t out[32]) {
    if (ikm == NULL || ikm_len == 0 || out == NULL)
        return -1;
    if (ikm_len > INT_MAX || salt_len > INT_MAX || info_len > INT_MAX)
        return -1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ uses EVP_KDF */
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL)
        return -1;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL)
        return -1;

    OSSL_PARAM params[5];
    int p = 0;
    char digest_name[] = "SHA256";
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", digest_name, 0);
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikm_len);
    if (salt != NULL && salt_len > 0)
        params[p++] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    if (info != NULL && info_len > 0)
        params[p++] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
    params[p] = OSSL_PARAM_construct_end();

    int ok = EVP_KDF_derive(kctx, out, 32, params) == 1 ? 0 : -1;
    EVP_KDF_CTX_free(kctx);
    return ok;
#else
    /* OpenSSL 1.1.0+ uses EVP_PKEY_derive with HKDF */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
        return -1;

    int ok = 0;
    do {
        if (EVP_PKEY_derive_init(pctx) != 1)
            break;
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1)
            break;
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) != 1)
            break;
        if (salt != NULL && salt_len > 0) {
            if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) != 1)
                break;
        }
        if (info != NULL && info_len > 0) {
            if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) != 1)
                break;
        }
        size_t outlen = 32;
        if (EVP_PKEY_derive(pctx, out, &outlen) != 1 || outlen != 32)
            break;
        ok = 1;
    } while (0);

    EVP_PKEY_CTX_free(pctx);
    return ok ? 0 : -1;
#endif
}

static uint8_t ipc_crypto_master_key[32];
static pthread_mutex_t ipc_crypto_master_lock = PTHREAD_MUTEX_INITIALIZER;
static int ipc_crypto_master_initialized = 0;
static int ipc_crypto_master_locked = 0;
static int ipc_crypto_cleanup_registered = 0;

static void
secure_memzero(void *ptr, size_t len) {
#if defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(HAVE_MEMSET_S)
    (void)memset_s(ptr, len, 0, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0)
        *p++ = 0;
#endif
}

static void
ipc_crypto_mask_failure(size_t payload_len) {
    const size_t MIN_PAD = 32;
    const size_t MAX_PAD = 4096;
    size_t work = payload_len;

    if (work < MIN_PAD)
        work = MIN_PAD;
    if (work > MAX_PAD)
        work = MAX_PAD;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return;

    uint8_t *scratch = calloc(1, work);
    if (scratch == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    uint8_t zero_key[32] = {0};
    uint8_t zero_nonce[IPC_CRYPTO_NONCE_LEN] = {0};
    uint8_t zero_tag[IPC_CRYPTO_TAG_LEN] = {0};
    uint8_t aad[sizeof(uint32_t) * 2] = {0};
    int len;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                IPC_CRYPTO_NONCE_LEN, NULL) == 1 &&
            EVP_DecryptInit_ex(ctx, NULL, NULL, zero_key, zero_nonce) == 1 &&
            EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) == 1) {
        size_t remaining = work;
        while (remaining > 0) {
            size_t chunk = remaining > (size_t)INT_MAX ? (size_t)INT_MAX : remaining;
            if (EVP_DecryptUpdate(ctx, scratch, &len, scratch, (int)chunk) != 1)
                break;
            remaining -= chunk;
        }
        (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                IPC_CRYPTO_TAG_LEN, zero_tag);
        (void)EVP_DecryptFinal_ex(ctx, scratch, &len);
    }

    OPENSSL_cleanse(scratch, work);
    free(scratch);
    EVP_CIPHER_CTX_free(ctx);
}

static void
ipc_crypto_master_cleanup(void) {
    secure_memzero(ipc_crypto_master_key, sizeof(ipc_crypto_master_key));
    /* Note: We intentionally do NOT call munlock() here.
     * This cleanup runs at exit via atexit(), potentially after pledge("")
     * on OpenBSD. munlock() would violate pledge and kill the process.
     * Since we're exiting, the OS will reclaim all memory anyway,
     * and we've already zeroed the sensitive data above. */
    ipc_crypto_master_locked = 0;
    ipc_crypto_master_initialized = 0;
}

static int
derive_key(const uint8_t *base, size_t base_len,
        const char *label, uint8_t out[32]) {
    size_t label_len = 0;
    if (label != NULL) {
        label_len = strlen(label);
        if (label_len > 1024)
            return -1;
    }
    /* Use HKDF with base key as IKM and label as info for domain separation */
    return hkdf_sha256(NULL, 0, base, base_len,
            (const uint8_t *)label, label_len, out);
}

int
ipc_crypto_system_init(void) {
    pthread_mutex_lock(&ipc_crypto_master_lock);
    if (!ipc_crypto_master_initialized) {
        if (RAND_bytes(ipc_crypto_master_key, sizeof(ipc_crypto_master_key)) != 1) {
            pthread_mutex_unlock(&ipc_crypto_master_lock);
            return -1;
        }
        if (!ipc_crypto_master_locked) {
            if (mlock(ipc_crypto_master_key, sizeof(ipc_crypto_master_key)) == 0)
                ipc_crypto_master_locked = 1;
        }
        if (!ipc_crypto_cleanup_registered) {
            if (atexit(ipc_crypto_master_cleanup) == 0)
                ipc_crypto_cleanup_registered = 1;
        }
        ipc_crypto_master_initialized = 1;
    }
    pthread_mutex_unlock(&ipc_crypto_master_lock);
    return 0;
}

static int
derive_base_key(uint32_t channel_id, uint8_t out[32]) {
    if (ipc_crypto_system_init() < 0)
        return -1;

    uint8_t channel_be[4];
    uint32_t value = htonl(channel_id);
    memcpy(channel_be, &value, sizeof(channel_be));

    /* Use HKDF with master key as IKM and channel ID as salt for domain separation */
    return hkdf_sha256(channel_be, sizeof(channel_be),
            ipc_crypto_master_key, sizeof(ipc_crypto_master_key),
            NULL, 0, out);
}

static int
derive_rekey_key(const uint8_t *base_key, uint32_t generation,
        const char *label, uint8_t out[32]) {
    /* Construct info parameter: "REKEY" || generation || label */
    uint32_t gen_be = htonl(generation);
    size_t label_len = label != NULL ? strlen(label) : 0;
    if (label_len > 1024)
        return -1;
    size_t info_len = 5 + sizeof(gen_be) + label_len;
    uint8_t *info = malloc(info_len);
    if (info == NULL)
        return -1;

    memcpy(info, "REKEY", 5);
    memcpy(info + 5, &gen_be, sizeof(gen_be));
    if (label_len > 0)
        memcpy(info + 5 + sizeof(gen_be), label, label_len);

    /* Use HKDF with base key as IKM and combined info for domain separation */
    int ret = hkdf_sha256(NULL, 0, base_key, 32, info, info_len, out);
    secure_memzero(info, info_len);
    free(info);
    return ret;
}

static int
ipc_crypto_set_directional_keys(struct ipc_crypto_state *state,
        enum ipc_crypto_role role) {
    const char *send_label;
    const char *recv_label;

    if (role == IPC_CRYPTO_ROLE_PARENT) {
        send_label = IPC_CRYPTO_LABEL_PARENT_SEND;
        recv_label = IPC_CRYPTO_LABEL_PARENT_RECV;
    } else {
        send_label = IPC_CRYPTO_LABEL_CHILD_SEND;
        recv_label = IPC_CRYPTO_LABEL_CHILD_RECV;
    }

    if (derive_key(state->base_key, sizeof(state->base_key), send_label,
                state->send_key) < 0)
        return -1;
    if (derive_key(state->base_key, sizeof(state->base_key), recv_label,
                state->recv_key) < 0)
        return -1;

    state->role = role;
    state->send_counter = 0;
    state->recv_counter = 0;
    state->send_generation = 0;
    state->recv_generation = 0;
    state->send_key_timestamp = time(NULL);
    state->recv_key_timestamp = time(NULL);

    return 0;
}

static int
ipc_crypto_rekey_send(struct ipc_crypto_state *state) {
    if (state == NULL)
        return -1;

    /* Check for generation overflow (extremely unlikely but handle safely).
     * This would require ~4 billion rekeys to trigger. Each rekey happens
     * after 2^63 messages or 7 days, making this practically impossible. */
    if (state->send_generation == UINT32_MAX) {
        /* Log this impossible event for debugging if it ever happens */
        return -1;
    }

    state->send_generation++;

    const char *send_label;

    if (state->role == IPC_CRYPTO_ROLE_PARENT) {
        send_label = IPC_CRYPTO_LABEL_PARENT_SEND;
    } else {
        send_label = IPC_CRYPTO_LABEL_CHILD_SEND;
    }

    /* Derive new send key from base_key with rekey generation */
    if (derive_rekey_key(state->base_key, state->send_generation,
                send_label, state->send_key) < 0)
        return -1;

    /* Reset send counter and update timestamp for new key generation */
    state->send_counter = 0;
    state->send_key_timestamp = time(NULL);

    return 0;
}

static int
ipc_crypto_rekey_recv(struct ipc_crypto_state *state) {
    if (state == NULL)
        return -1;

    /* Check for generation overflow (extremely unlikely but handle safely) */
    if (state->recv_generation == UINT32_MAX)
        return -1;

    state->recv_generation++;

    const char *recv_label;

    if (state->role == IPC_CRYPTO_ROLE_PARENT) {
        recv_label = IPC_CRYPTO_LABEL_PARENT_RECV;
    } else {
        recv_label = IPC_CRYPTO_LABEL_CHILD_RECV;
    }

    /* Derive new recv key from base_key with rekey generation */
    if (derive_rekey_key(state->base_key, state->recv_generation,
                recv_label, state->recv_key) < 0)
        return -1;

    /* Reset recv counter and update timestamp for new key generation */
    state->recv_counter = 0;
    state->recv_key_timestamp = time(NULL);

    return 0;
}

int
ipc_crypto_channel_init(struct ipc_crypto_state *state, uint32_t channel_id,
        enum ipc_crypto_role role) {
    if (state == NULL)
        return -1;

    if (derive_base_key(channel_id, state->base_key) < 0)
        return -1;

    state->channel_id = channel_id;
    state->send_counter = 0;

    return ipc_crypto_set_directional_keys(state, role);
}

int
ipc_crypto_channel_set_role(struct ipc_crypto_state *state,
        enum ipc_crypto_role role) {
    if (state == NULL)
        return -1;

    return ipc_crypto_set_directional_keys(state, role);
}

static void
format_nonce(const struct ipc_crypto_state *state, uint64_t counter,
        uint8_t nonce[IPC_CRYPTO_NONCE_LEN]) {
    uint32_t channel_be = htonl(state->channel_id);
    memcpy(nonce, &channel_be, sizeof(channel_be));

    uint64_t counter_be = host_to_be64(counter);
    memcpy(nonce + sizeof(channel_be), &counter_be, sizeof(counter_be));
}

static uint64_t
extract_counter_from_nonce(const uint8_t nonce[IPC_CRYPTO_NONCE_LEN]) {
    uint64_t counter_be;
    memcpy(&counter_be, nonce + sizeof(uint32_t), sizeof(counter_be));

    uint32_t high = ntohl((uint32_t)(counter_be >> 32));
    uint32_t low = ntohl((uint32_t)(counter_be & 0xffffffffu));
    return ((uint64_t)high << 32) | low;
}


static int
seal_internal(struct ipc_crypto_state *state, const uint8_t *plaintext,
        size_t plaintext_len, uint8_t *frame, size_t frame_len) {
    (void)frame_len;

    /* Check if we need to rekey send direction based on counter threshold or time */
    time_t now = time(NULL);
    time_t key_age = now - state->send_key_timestamp;

    if (state->send_counter >= IPC_CRYPTO_REKEY_THRESHOLD ||
        key_age >= IPC_CRYPTO_REKEY_INTERVAL) {
        if (ipc_crypto_rekey_send(state) < 0)
            return -1;
    }

    struct __attribute__((__packed__)) ipc_frame_header {
        uint32_t magic;
        uint32_t length;
        uint32_t generation;
        uint8_t nonce[IPC_CRYPTO_NONCE_LEN];
    } header;

    header.magic = htonl(IPC_CRYPTO_MAGIC);
    header.length = htonl((uint32_t)plaintext_len);
    header.generation = htonl(state->send_generation);

    if (state->send_counter == UINT64_MAX)
        return -1; /* counter would wrap and re-use nonce */

    uint64_t counter = ++state->send_counter;
    format_nonce(state, counter, header.nonce);

    memcpy(frame, &header, sizeof(header));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    int ok = 0;
    int len;
    uint8_t *ciphertext = frame + sizeof(header);
    uint8_t *tag = frame + sizeof(header) + plaintext_len;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                    IPC_CRYPTO_NONCE_LEN, NULL) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, state->send_key,
                    header.nonce) != 1)
            break;
        /* AAD includes magic, length, and generation for integrity */
        if (EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *)&header,
                    sizeof(header.magic) + sizeof(header.length) + sizeof(header.generation)) != 1)
            break;
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                    (int)plaintext_len) != 1)
            break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                    IPC_CRYPTO_TAG_LEN, tag) != 1)
            break;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int
ipc_crypto_seal(struct ipc_crypto_state *state, const uint8_t *plaintext,
        size_t plaintext_len, uint8_t **frame, size_t *frame_len) {
    if (state == NULL || plaintext == NULL || frame == NULL || frame_len == NULL)
        return -1;

    if (plaintext_len > UINT32_MAX)
        return -1;

    size_t overhead = IPC_CRYPTO_HEADER_LEN + IPC_CRYPTO_TAG_LEN;
    if (overhead < IPC_CRYPTO_HEADER_LEN)
        return -1; /* overflow */
    if (plaintext_len > SIZE_MAX - overhead)
        return -1; /* would overflow total length */

    size_t total_len = overhead + plaintext_len;
    uint8_t *buffer = malloc(total_len);
    if (buffer == NULL)
        return -1;

    if (seal_internal(state, plaintext, plaintext_len, buffer, total_len) < 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_len = total_len;
    return 0;
}

int
ipc_crypto_open(struct ipc_crypto_state *state, const uint8_t *frame,
        size_t frame_len, size_t max_payload_len, uint8_t **plaintext,
        size_t *plaintext_len) {
    if (state == NULL || frame == NULL || plaintext == NULL || plaintext_len == NULL)
        return -1;

    if (frame_len < IPC_CRYPTO_HEADER_LEN + IPC_CRYPTO_TAG_LEN) {
        ipc_crypto_mask_failure(0);
        return -1;
    }

    struct __attribute__((__packed__)) ipc_frame_header {
        uint32_t magic;
        uint32_t length;
        uint32_t generation;
        uint8_t nonce[IPC_CRYPTO_NONCE_LEN];
    } header;

    memcpy(&header, frame, sizeof(header));

    if (ntohl(header.magic) != IPC_CRYPTO_MAGIC) {
        ipc_crypto_mask_failure(0);
        return -1;
    }

    uint32_t payload_len = ntohl(header.length);
    uint32_t msg_generation = ntohl(header.generation);

    /* Validate payload_len against maximum before allocation (defense-in-depth) */
    if (payload_len > max_payload_len) {
        ipc_crypto_mask_failure(payload_len);
        return -1;
    }

    size_t expected = IPC_CRYPTO_HEADER_LEN + payload_len + IPC_CRYPTO_TAG_LEN;
    if (frame_len != expected) {
        ipc_crypto_mask_failure(payload_len);
        return -1;
    }

    /* Extract counter from nonce for replay protection */
    uint64_t msg_counter = extract_counter_from_nonce(header.nonce);

    const uint8_t *ciphertext = frame + IPC_CRYPTO_HEADER_LEN;
    const uint8_t *tag = frame + IPC_CRYPTO_HEADER_LEN + payload_len;

    uint8_t *output = malloc(payload_len > 0 ? payload_len : 1);
    if (output == NULL) {
        ipc_crypto_mask_failure(payload_len);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(output);
        ipc_crypto_mask_failure(payload_len);
        return -1;
    }

    int ok = 0;
    int len;

    /* Handle generation mismatch - explicit rekey detection via protocol */
    if (msg_generation < state->recv_generation) {
        /* Message from old generation - replay attack */
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(output, payload_len > 0 ? payload_len : 1);
        free(output);
        warn("IPC replay attack: msg_generation=%u < recv_generation=%u",
                msg_generation, state->recv_generation);
        ipc_crypto_mask_failure(payload_len);
        errno = EBADMSG;
        return -1;
    }

    /* Reject excessive generation gap to prevent DoS via forced rekey loop */
    if (msg_generation - state->recv_generation > IPC_CRYPTO_MAX_GENERATION_GAP) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(output, payload_len > 0 ? payload_len : 1);
        free(output);
        warn("IPC generation gap too large: msg_generation=%u, recv_generation=%u, gap=%u",
                msg_generation, state->recv_generation,
                msg_generation - state->recv_generation);
        ipc_crypto_mask_failure(payload_len);
        errno = EBADMSG;
        return -1;
    }

    /* Advance recv_generation to match sender if needed */
    while (state->recv_generation < msg_generation) {
        if (ipc_crypto_rekey_recv(state) < 0) {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(output, payload_len > 0 ? payload_len : 1);
            free(output);
            ipc_crypto_mask_failure(payload_len);
            return -1;
        }
    }

    /* Within same generation, enforce strictly monotonic counters */
    if (msg_counter <= state->recv_counter) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(output, payload_len > 0 ? payload_len : 1);
        free(output);
        warn("IPC replay attack: msg_counter=%llu <= recv_counter=%llu (generation=%u)",
                (unsigned long long)msg_counter,
                (unsigned long long)state->recv_counter,
                msg_generation);
        ipc_crypto_mask_failure(payload_len);
        errno = EBADMSG;
        return -1;
    }

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                    IPC_CRYPTO_NONCE_LEN, NULL) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, state->recv_key,
                    header.nonce) != 1)
            break;
        /* AAD includes magic, length, and generation for integrity */
        if (EVP_DecryptUpdate(ctx, NULL, &len, (uint8_t *)&header,
                    sizeof(header.magic) + sizeof(header.length) + sizeof(header.generation)) != 1)
            break;
        if (payload_len > 0) {
            if (EVP_DecryptUpdate(ctx, output, &len, ciphertext,
                        (int)payload_len) != 1)
                break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                    IPC_CRYPTO_TAG_LEN, (void *)tag) != 1)
            break;
        if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1)
            break;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        OPENSSL_cleanse(output, payload_len > 0 ? payload_len : 1);
        free(output);
        ipc_crypto_mask_failure(payload_len);
        return -1;
    }

    /* Update recv_counter to enforce monotonicity for next message */
    state->recv_counter = msg_counter;

    *plaintext = output;
    *plaintext_len = payload_len;
    return 0;
}


int
ipc_crypto_send_msg(struct ipc_crypto_state *state, int sockfd,
        const void *payload, size_t payload_len, int fd_to_send) {
    if (state == NULL || (payload_len > 0 && payload == NULL))
        return -1;

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (ipc_crypto_seal(state, payload, payload_len, &frame, &frame_len) < 0)
        return -1;

    uint32_t frame_len_net = htonl((uint32_t)frame_len);
    struct iovec iov[2];
    iov[0].iov_base = &frame_len_net;
    iov[0].iov_len = sizeof(frame_len_net);
    iov[1].iov_base = frame;
    iov[1].iov_len = frame_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    char control_buf[CMSG_SPACE(sizeof(int))];
    if (fd_to_send >= 0) {
        msg.msg_control = control_buf;
        msg.msg_controllen = sizeof(control_buf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
    }

    ssize_t sent = sendmsg(sockfd, &msg,
#ifdef MSG_NOSIGNAL
            MSG_NOSIGNAL
#else
            0
#endif
            );
    free(frame);

    if (sent < 0)
        return -1;

    return 0;
}

int
ipc_crypto_recv_msg(struct ipc_crypto_state *state, int sockfd,
        size_t max_payload_len, uint8_t **plaintext, size_t *plaintext_len,
        int *received_fd) {
    if (state == NULL || plaintext == NULL || plaintext_len == NULL)
        return -1;

    /* Read the 4-byte frame length prefix using recvmsg() so that any
     * SCM_RIGHTS ancillary data sent alongside it is not discarded.
     * The sender packs prefix + frame + fd into a single sendmsg(). */
    uint32_t frame_len_net;
    int prefix_fd = -1;
    {
        struct iovec prefix_iov;
        prefix_iov.iov_base = &frame_len_net;
        prefix_iov.iov_len = sizeof(frame_len_net);

        char prefix_control[CMSG_SPACE(sizeof(int))];
        struct msghdr prefix_msg;
        memset(&prefix_msg, 0, sizeof(prefix_msg));
        prefix_msg.msg_iov = &prefix_iov;
        prefix_msg.msg_iovlen = 1;
        prefix_msg.msg_control = prefix_control;
        prefix_msg.msg_controllen = sizeof(prefix_control);

        ssize_t prefix_ret;
        do {
            prefix_ret = recvmsg(sockfd, &prefix_msg, MSG_WAITALL);
        } while (prefix_ret < 0 && errno == EINTR);

        if (prefix_ret <= 0)
            return (int)prefix_ret;

        if ((size_t)prefix_ret != sizeof(frame_len_net)) {
            errno = EIO;
            return -1;
        }

        struct cmsghdr *prefix_cmsg = CMSG_FIRSTHDR(&prefix_msg);
        if (prefix_cmsg != NULL && prefix_cmsg->cmsg_level == SOL_SOCKET &&
                prefix_cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&prefix_fd, CMSG_DATA(prefix_cmsg), sizeof(int));
        }
    }

    uint32_t frame_len = ntohl(frame_len_net);
    size_t max_frame = IPC_CRYPTO_HEADER_LEN + max_payload_len + IPC_CRYPTO_TAG_LEN;
    if (frame_len == 0 || frame_len > max_frame) {
        if (prefix_fd >= 0)
            close(prefix_fd);
        errno = EMSGSIZE;
        return -1;
    }

    uint8_t *cipher = malloc(frame_len);
    if (cipher == NULL) {
        if (prefix_fd >= 0)
            close(prefix_fd);
        return -1;
    }

    struct iovec iov;
    iov.iov_base = cipher;
    iov.iov_len = frame_len;

    char control_buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);

    ssize_t ret;
    do {
        ret = recvmsg(sockfd, &msg, MSG_WAITALL);
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        free(cipher);
        if (prefix_fd >= 0)
            close(prefix_fd);
        return (int)ret;
    }

    /* Reject truncated payload or ancillary data to avoid using undefined data
     * (e.g., partially received SCM_RIGHTS file descriptors). */
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        free(cipher);
        if (prefix_fd >= 0)
            close(prefix_fd);
        errno = EMSGSIZE;
        return -1;
    }

    if ((size_t)ret != frame_len) {
        free(cipher);
        if (prefix_fd >= 0)
            close(prefix_fd);
        errno = EIO;
        return -1;
    }

    /* Merge fd from prefix read and frame read. The fd typically arrives
     * with the prefix since the sender uses a single sendmsg(). */
    int fd_received = -1;
    if (received_fd != NULL)
        *received_fd = -1;

    int frame_fd = -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
        memcpy(&frame_fd, CMSG_DATA(cmsg), sizeof(int));
    }

    if (prefix_fd >= 0) {
        fd_received = prefix_fd;
        if (frame_fd >= 0)
            close(frame_fd);
    } else {
        fd_received = frame_fd;
    }

    if (ipc_crypto_open(state, cipher, frame_len, max_payload_len,
                plaintext, plaintext_len) < 0) {
        free(cipher);
        if (fd_received >= 0)
            close(fd_received);
        errno = EBADMSG;
        return -1;
    }

    if (received_fd != NULL)
        *received_fd = fd_received;
    else if (fd_received >= 0)
        close(fd_received);

    free(cipher);
    return 1;
}

void
ipc_crypto_state_clear(struct ipc_crypto_state *state) {
    if (state == NULL)
        return;
    secure_memzero(state, sizeof(*state));
}
