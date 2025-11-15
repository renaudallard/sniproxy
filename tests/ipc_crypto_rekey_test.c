/*
 * Test for IPC crypto automatic rekeying functionality
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ipc_crypto.h"

/* Test that rekey happens at threshold and keys change */
static void test_rekey_at_threshold(void) {
    struct ipc_crypto_state parent_state;
    struct ipc_crypto_state child_state;

    printf("Test: Rekey at threshold...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);
    assert(ipc_crypto_channel_init(&child_state, 0x54455354, IPC_CRYPTO_ROLE_CHILD) == 0);

    /* Save original keys */
    uint8_t orig_parent_send[32];
    memcpy(orig_parent_send, parent_state.send_key, 32);

    /* Manually set counter at threshold (will trigger rekey on next seal) */
    parent_state.send_counter = ((uint64_t)1 << 63);
    assert(parent_state.send_generation == 0);
    assert(parent_state.recv_generation == 0);

    /* Send a message - should trigger rekey */
    const uint8_t test_msg[] = "test message";
    uint8_t *frame = NULL;
    size_t frame_len = 0;

    assert(ipc_crypto_seal(&parent_state, test_msg, sizeof(test_msg), &frame, &frame_len) == 0);

    /* Check that send rekey happened */
    assert(parent_state.send_generation == 1);
    assert(parent_state.recv_generation == 0); /* Recv side unchanged */
    assert(parent_state.send_counter == 1); /* Reset to 0, then incremented for message */

    /* Check that send key changed */
    assert(memcmp(orig_parent_send, parent_state.send_key, 32) != 0);

    /* Child should be able to receive if it rekeys too */
    child_state.recv_counter = ((uint64_t)1 << 63); /* Simulate it was at same point */

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    assert(ipc_crypto_open(&child_state, frame, frame_len, 1024, &plaintext, &plaintext_len) == 0);
    assert(plaintext_len == sizeof(test_msg));
    assert(memcmp(plaintext, test_msg, sizeof(test_msg)) == 0);
    assert(child_state.recv_generation == 1); /* Recv side rekeyed */
    assert(child_state.send_generation == 0); /* Send side unchanged */

    free(frame);
    free(plaintext);
    ipc_crypto_state_clear(&parent_state);
    ipc_crypto_state_clear(&child_state);

    printf("  PASSED\n");
}

/* Test that generation overflow is handled */
static void test_generation_overflow_protection(void) {
    struct ipc_crypto_state state;

    printf("Test: Generation overflow protection...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);

    /* Set send generation to max */
    state.send_generation = UINT32_MAX;
    state.send_counter = ((uint64_t)1 << 63);

    /* Try to seal - should fail due to generation overflow */
    const uint8_t test_msg[] = "test";
    uint8_t *frame = NULL;
    size_t frame_len = 0;

    int result = ipc_crypto_seal(&state, test_msg, sizeof(test_msg), &frame, &frame_len);
    assert(result < 0); /* Should fail */

    ipc_crypto_state_clear(&state);

    printf("  PASSED\n");
}

/* Test normal operation without rekey */
static void test_normal_operation(void) {
    struct ipc_crypto_state parent_state;
    struct ipc_crypto_state child_state;

    printf("Test: Normal operation without rekey...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);
    assert(ipc_crypto_channel_init(&child_state, 0x54455354, IPC_CRYPTO_ROLE_CHILD) == 0);

    /* Send multiple messages - should not trigger rekey */
    for (int i = 0; i < 100; i++) {
        const uint8_t test_msg[] = "test message";
        uint8_t *frame = NULL;
        size_t frame_len = 0;

        assert(ipc_crypto_seal(&parent_state, test_msg, sizeof(test_msg), &frame, &frame_len) == 0);

        uint8_t *plaintext = NULL;
        size_t plaintext_len = 0;

        assert(ipc_crypto_open(&child_state, frame, frame_len, 1024, &plaintext, &plaintext_len) == 0);
        assert(plaintext_len == sizeof(test_msg));
        assert(memcmp(plaintext, test_msg, sizeof(test_msg)) == 0);

        free(frame);
        free(plaintext);
    }

    /* Should not have rekeyed */
    assert(parent_state.send_generation == 0);
    assert(parent_state.recv_generation == 0);
    assert(child_state.send_generation == 0);
    assert(child_state.recv_generation == 0);
    assert(parent_state.send_counter == 100);
    assert(child_state.recv_counter == 100);

    ipc_crypto_state_clear(&parent_state);
    ipc_crypto_state_clear(&child_state);

    printf("  PASSED\n");
}

int main(void) {
    printf("IPC Crypto Rekey Tests\n");
    printf("======================\n\n");

    test_normal_operation();
    test_rekey_at_threshold();
    test_generation_overflow_protection();

    printf("\nAll tests PASSED!\n");
    return 0;
}
