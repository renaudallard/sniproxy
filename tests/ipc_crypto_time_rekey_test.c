/*
 * Test for IPC crypto time-based automatic rekeying functionality
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../src/ipc_crypto.h"

/* Test that rekey happens after time interval */
static void test_time_based_rekey(void) {
    struct ipc_crypto_state parent_state;
    struct ipc_crypto_state child_state;

    printf("Test: Time-based rekey after one week...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);
    assert(ipc_crypto_channel_init(&child_state, 0x54455354, IPC_CRYPTO_ROLE_CHILD) == 0);

    /* Save original keys */
    uint8_t orig_parent_send[32];
    memcpy(orig_parent_send, parent_state.send_key, 32);

    /* Verify initial generation is 0 */
    assert(parent_state.send_generation == 0);
    assert(parent_state.recv_generation == 0);

    /* Send a few normal messages first to establish non-zero counters */
    for (int i = 0; i < 10; i++) {
        const uint8_t msg[] = "setup message";
        uint8_t *setup_frame = NULL;
        size_t setup_frame_len = 0;
        uint8_t *setup_plaintext = NULL;
        size_t setup_plaintext_len = 0;

        assert(ipc_crypto_seal(&parent_state, msg, sizeof(msg), &setup_frame, &setup_frame_len) == 0);
        assert(ipc_crypto_open(&child_state, setup_frame, setup_frame_len, 1024, &setup_plaintext, &setup_plaintext_len) == 0);

        free(setup_frame);
        free(setup_plaintext);
    }

    /* Verify counters are now at 10 */
    assert(parent_state.send_counter == 10);
    assert(child_state.recv_counter == 10);

    /* Simulate one week passing by setting timestamp to one week ago */
    parent_state.send_key_timestamp = time(NULL) - (7 * 24 * 60 * 60);

    /* Send a message - should trigger time-based rekey */
    const uint8_t test_msg[] = "test message after one week";
    uint8_t *frame = NULL;
    size_t frame_len = 0;

    assert(ipc_crypto_seal(&parent_state, test_msg, sizeof(test_msg), &frame, &frame_len) == 0);

    /* Check that send rekey happened due to time */
    assert(parent_state.send_generation == 1);
    assert(parent_state.recv_generation == 0); /* Recv side unchanged */

    /* Check that send key changed */
    assert(memcmp(orig_parent_send, parent_state.send_key, 32) != 0);

    /* Check that timestamp was updated to current time */
    time_t now = time(NULL);
    assert(parent_state.send_key_timestamp >= now - 2 &&
           parent_state.send_key_timestamp <= now + 2);

    /* Child should be able to receive and will auto-detect rekey from counter */
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    assert(ipc_crypto_open(&child_state, frame, frame_len, 1024, &plaintext, &plaintext_len) == 0);
    assert(plaintext_len == sizeof(test_msg));
    assert(memcmp(plaintext, test_msg, sizeof(test_msg)) == 0);
    assert(child_state.recv_generation == 1); /* Recv side auto-rekeyed */

    free(frame);
    free(plaintext);
    ipc_crypto_state_clear(&parent_state);
    ipc_crypto_state_clear(&child_state);

    printf("  PASSED\n");
}

/* Test that both counter and time triggers work independently */
static void test_dual_trigger(void) {
    struct ipc_crypto_state parent_state;

    printf("Test: Both counter and time triggers...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);

    /* Test counter trigger */
    parent_state.send_counter = ((uint64_t)1 << 63);
    const uint8_t test_msg1[] = "counter trigger";
    uint8_t *frame1 = NULL;
    size_t frame_len1 = 0;

    assert(ipc_crypto_seal(&parent_state, test_msg1, sizeof(test_msg1), &frame1, &frame_len1) == 0);
    assert(parent_state.send_generation == 1);
    free(frame1);

    /* Test time trigger on next generation */
    parent_state.send_key_timestamp = time(NULL) - (7 * 24 * 60 * 60);
    const uint8_t test_msg2[] = "time trigger";
    uint8_t *frame2 = NULL;
    size_t frame_len2 = 0;

    assert(ipc_crypto_seal(&parent_state, test_msg2, sizeof(test_msg2), &frame2, &frame_len2) == 0);
    assert(parent_state.send_generation == 2);
    free(frame2);

    ipc_crypto_state_clear(&parent_state);

    printf("  PASSED\n");
}

/* Test that recent keys don't trigger rekey */
static void test_no_premature_rekey(void) {
    struct ipc_crypto_state parent_state;

    printf("Test: No premature rekey for recent keys...\n");

    assert(ipc_crypto_system_init() == 0);
    assert(ipc_crypto_channel_init(&parent_state, 0x54455354, IPC_CRYPTO_ROLE_PARENT) == 0);

    /* Send multiple messages over 6 days (not yet 7 days) */
    for (int day = 0; day < 6; day++) {
        /* Simulate one day passing */
        parent_state.send_key_timestamp = time(NULL) - (day * 24 * 60 * 60);

        const uint8_t test_msg[] = "test message";
        uint8_t *frame = NULL;
        size_t frame_len = 0;

        assert(ipc_crypto_seal(&parent_state, test_msg, sizeof(test_msg), &frame, &frame_len) == 0);

        /* Should not have rekeyed yet */
        assert(parent_state.send_generation == 0);

        free(frame);
    }

    ipc_crypto_state_clear(&parent_state);

    printf("  PASSED\n");
}

int main(void) {
    printf("IPC Crypto Time-Based Rekey Tests\n");
    printf("==================================\n\n");

    test_no_premature_rekey();
    test_time_based_rekey();
    test_dual_trigger();

    printf("\nAll tests PASSED!\n");
    return 0;
}
