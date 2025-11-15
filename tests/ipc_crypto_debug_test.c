/*
 * Debug test for IPC crypto rekey
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ipc_crypto.h"

static void print_key(const char *label, const uint8_t *key, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(void) {
    struct ipc_crypto_state parent_state;
    struct ipc_crypto_state child_state;

    printf("Debug: IPC Crypto Rekey\n");
    printf("=======================\n\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);
    assert(ipc_crypto_channel_init(&child_state, 0x54455354, IPC_CRYPTO_ROLE_CHILD) == 0);

    printf("Initial state:\n");
    print_key("Parent base_key", parent_state.base_key, 32);
    print_key("Child base_key ", child_state.base_key, 32);
    print_key("Parent send_key", parent_state.send_key, 32);
    print_key("Child recv_key ", child_state.recv_key, 32);
    printf("Parent send_gen: %u, Child recv_gen: %u\n\n",
           parent_state.send_generation, child_state.recv_generation);

    /* Set counter at threshold */
    parent_state.send_counter = ((uint64_t)1 << 63);
    child_state.recv_counter = ((uint64_t)1 << 63);

    /* Send a message */
    const uint8_t test_msg[] = "test message";
    uint8_t *frame = NULL;
    size_t frame_len = 0;

    printf("Sealing message (should trigger rekey)...\n");
    assert(ipc_crypto_seal(&parent_state, test_msg, sizeof(test_msg), &frame, &frame_len) == 0);

    printf("After parent seal:\n");
    print_key("Parent send_key", parent_state.send_key, 32);
    printf("Parent send_gen: %u, counter: %lu\n\n",
           parent_state.send_generation, parent_state.send_counter);

    /* Try to open */
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    printf("Opening message (should trigger recv rekey)...\n");
    int result = ipc_crypto_open(&child_state, frame, frame_len, 1024, &plaintext, &plaintext_len);

    printf("After child open (result=%d):\n", result);
    print_key("Child recv_key ", child_state.recv_key, 32);
    printf("Child recv_gen: %u, counter: %lu\n\n",
           child_state.recv_generation, child_state.recv_counter);

    if (result == 0) {
        printf("Success! Message decrypted.\n");
        printf("Plaintext length: %zu\n", plaintext_len);
        printf("Match: %s\n", memcmp(plaintext, test_msg, sizeof(test_msg)) == 0 ? "YES" : "NO");
        free(plaintext);
    } else {
        printf("FAILED to decrypt!\n");
    }

    free(frame);
    ipc_crypto_state_clear(&parent_state);
    ipc_crypto_state_clear(&child_state);

    return result == 0 ? 0 : 1;
}
