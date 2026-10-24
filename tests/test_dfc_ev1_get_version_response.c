#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"

#include <string.h>

static void exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, 64, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void expect_fixed_frame(
    DfcVirtualPiccSession* session,
    DfcSecureMessaging* oracle,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected,
    size_t expected_len) {
    munit_assert_true(dfc_secure_messaging_update_ev1_command(oracle, command[1], NULL, 0));

    uint8_t response[64];
    size_t response_len = 0;
    exchange(session, command, command_len, response, &response_len);
    munit_assert_size(response_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, response, expected);
}

static void run_terminal_frame_case(uint8_t cipher, size_t key_len) {
    DfcCredential credential;
    load_standard_credential(&credential);
    credential.card.generation = DfcGenerationEv1;
    credential.card.storage = 4096;

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t key[24] = {0};
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    DfcSecureMessaging* oracle = dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    munit_assert_not_null(oracle);

    const uint8_t get_version[] = {0x90, DFC_CMD_GET_VERSION, 0, 0, 0};
    const uint8_t additional_frame[] = {0x90, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 0};
    const uint8_t frame_one[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05, 0x91, 0xAF};
    const uint8_t frame_two[] = {0x04, 0x01, 0x01, 0x01, 0x03, 0x18, 0x05, 0x91, 0xAF};
    expect_fixed_frame(
        session, oracle, get_version, sizeof(get_version), frame_one, sizeof(frame_one));
    expect_fixed_frame(
        session, oracle, additional_frame, sizeof(additional_frame), frame_two, sizeof(frame_two));

    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(oracle, DFC_CMD_ADDITIONAL_FRAME, NULL, 0));
    uint8_t response[64];
    size_t response_len = 0;
    exchange(session, additional_frame, sizeof(additional_frame), response, &response_len);
    munit_assert_size(response_len, ==, 14 + DFC_WIRE_MAC_LENGTH + 2);
    const uint8_t frame_three[] = {
        0x04,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x24,
    };
    munit_assert_memory_equal(sizeof(frame_three), response, frame_three);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    uint8_t clear[64];
    size_t clear_len = dfc_secure_messaging_unwrap_ev1_response(
        oracle, DFC_STATUS_OK, response, response_len - 2, clear, sizeof(clear));
    munit_assert_size(clear_len, ==, sizeof(frame_three));
    munit_assert_memory_equal(sizeof(frame_three), clear, frame_three);

    const uint8_t get_key_settings[] = {0x90, DFC_CMD_GET_KEY_SETTINGS, 0, 0, 0};
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(oracle, DFC_CMD_GET_KEY_SETTINGS, NULL, 0));
    exchange(session, get_key_settings, sizeof(get_key_settings), response, &response_len);
    munit_assert_size(response_len, ==, 2 + DFC_WIRE_MAC_LENGTH + 2);
    clear_len = dfc_secure_messaging_unwrap_ev1_response(
        oracle, DFC_STATUS_OK, response, response_len - 2, clear, sizeof(clear));
    munit_assert_size(clear_len, ==, 2);
    munit_assert_uint8(clear[0], ==, credential.picc_key_settings_1);
    munit_assert_uint8(clear[1], ==, credential.picc_key_settings_2);

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
}

static MunitResult test_get_version_macs_only_terminal_frame_and_keeps_chain(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    run_terminal_frame_case(DFC_CMD_AUTHENTICATE_ISO, 8);
    run_terminal_frame_case(DFC_CMD_AUTHENTICATE_ISO, 16);
    run_terminal_frame_case(DFC_CMD_AUTHENTICATE_ISO, 24);
    run_terminal_frame_case(DFC_CMD_AUTHENTICATE_AES, 16);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {
        "/terminal-frame-only",
        test_get_version_macs_only_terminal_frame_and_keeps_chain,
        NULL,
        NULL,
        MUNIT_TEST_OPTION_NONE,
        NULL,
    },
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite =
    {"/dfc_ev1_get_version_response", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
