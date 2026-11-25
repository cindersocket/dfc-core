/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2026 CinderSocket
 *
 * Regression tests for dfc_emulator_handle_command_secured, the EV2
 * secure-messaging envelope the on-device (Flipper) listener wraps around every
 * command. The listener stages a transport prefix in tx_buffer BEFORE calling
 * the handler (the ISO-DEP PCB byte, when the firmware has no type_4_tag layer),
 * then wraps the native response back into ISO 7816 with
 * dfc_wrap_native_response_as_iso7816(prefix_len = <that prefix>).
 *
 * The contract the handler MUST honour: append the response after whatever is
 * already in tx_buffer; never reset it. A handler that reset tx_buffer dropped
 * the prefix, so the ISO wrapper then read the native status byte (0xAF for
 * GetVersion's first frame) as the prefix and the first data byte (0x04, the NXP
 * vendor id) as the status word. GetVersion came back as
 *   AF 01 01 33 00 1A 05 91 04
 * instead of
 *   04 01 01 33 00 1A 05 91 AF
 * so the vendor id was gone and readers no longer saw an NXP DESFire EV3.
 */
#include "dfc_common.h"
#include "dfc_credential.h"
#include "dfc_emulator.h"
#include "dfc_ev2_crypto.h"
#include "dfc_port_host.h"

#include "munit/munit.h"

#include <string.h>

// A bare EV3 / 8 KiB card with no stored version override, so GetVersion answers
// from build_default_version_frame: 04 01 01 33 00 1A 05 (NXP, type 1, subtype
// 1, HW major 0x33 = EV3, minor 0, storage 0x1A = 8 KiB, protocol 0x05).
static void make_ev3_8k_card(DfcCredential* credential) {
    dfc_credential_clear(credential);
    const uint8_t uid[] = {0x04, 0xA1, 0x7C, 0x6E, 0x9B, 0x2D, 0x58};
    memcpy(credential->uid, uid, sizeof(uid));
    credential->uid_len = sizeof(uid);
    credential->card.generation = DfcGenerationEv3;
    credential->card.storage = 8192;
    credential->card.has_hardware_version = false;
    credential->card.has_software_version = false;
}

// The expected native GetVersion first frame body (status byte excluded).
static const uint8_t kEv3_8k_hw_version[] = {0x04, 0x01, 0x01, 0x33, 0x00, 0x1A, 0x05};

static void activate_ev2_session(DfcEmulator* emulator) {
    emulator->ev2_session_active = true;
    emulator->ev2_transaction_identifier[0] = 0x11;
    emulator->ev2_transaction_identifier[1] = 0x22;
    emulator->ev2_transaction_identifier[2] = 0x33;
    emulator->ev2_transaction_identifier[3] = 0x44;
    memset(emulator->ev2_session_mac_key, 0x5A, sizeof(emulator->ev2_session_mac_key));
}

static void
    assert_plain_failure_after_prefix(const DfcByteBuf* tx, uint8_t prefix, uint8_t status) {
    const uint8_t expected[] = {prefix, status};
    munit_assert_size(dfc_bytebuf_get_size_bytes(tx), ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), dfc_bytebuf_get_data(tx), expected);
}

static MunitResult
    test_secured_plain_getversion_preserves_prefix(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    munit_assert_int(emulator->ev2_session_active, ==, 0);

    // Stand in for the listener: one PCB prefix byte already in tx_buffer.
    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x02;
    dfc_bytebuf_append_byte(&tx, prefix);

    const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, get_version, sizeof(get_version), &tx, NULL));

    // tx_buffer must now be: [prefix][AF][7-byte HW version]. The prefix survives.
    const uint8_t* data = dfc_bytebuf_get_data(&tx);
    munit_assert_size(dfc_bytebuf_get_size_bytes(&tx), ==, 1u + 1u + sizeof(kEv3_8k_hw_version));
    munit_assert_uint8(data[0], ==, prefix);
    munit_assert_uint8(data[1], ==, DFC_CMD_ADDITIONAL_FRAME);
    munit_assert_memory_equal(sizeof(kEv3_8k_hw_version), data + 2, kEv3_8k_hw_version);
    // The NXP vendor id must be the first version octet, right after the status.
    munit_assert_uint8(data[2], ==, 0x04);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

// End-to-end: the native response the handler builds, once run through the ISO
// wrapper exactly as the listener does, is the EV3 8 KiB frame a reader expects.
static MunitResult test_secured_getversion_wraps_to_iso7816_ev3_8k(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x02;
    dfc_bytebuf_append_byte(&tx, prefix);

    const uint8_t get_version[] = {DFC_CMD_GET_VERSION};
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, get_version, sizeof(get_version), &tx, NULL));

    uint8_t iso[32];
    size_t iso_len = 0;
    munit_assert_true(dfc_wrap_native_response_as_iso7816(
        dfc_bytebuf_get_data(&tx),
        dfc_bytebuf_get_size_bytes(&tx),
        1 /* prefix_len: one PCB byte */,
        iso,
        sizeof(iso),
        &iso_len));

    // prefix, then the 7 version octets, then SW = 91 AF (additional frame).
    const uint8_t expected[] = {
        0x02, 0x04, 0x01, 0x01, 0x33, 0x00, 0x1A, 0x05, 0x91, DFC_CMD_ADDITIONAL_FRAME};
    munit_assert_size(iso_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), iso, expected);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

// A secured command rejected before dispatch must append its exact status after
// the prefix, not reset the buffer.
static MunitResult
    test_secured_integrity_error_preserves_prefix(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    activate_ev2_session(emulator);

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x03;
    dfc_bytebuf_append_byte(&tx, prefix);

    // ChangeKeyEV2 (0xC6) requires a valid secured body and MAC. This deliberately
    // malformed frame must take the invalid-envelope branch.
    const uint8_t secured_cmd[] = {DFC_CMD_CHANGE_KEY_EV2, 0x00, 0x11, 0x22, 0x33, 0x44};
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, secured_cmd, sizeof(secured_cmd), &tx, NULL));

    assert_plain_failure_after_prefix(&tx, prefix, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_false(emulator->ev2_session_active);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

// Exercise the complete successful envelope: verify a command MAC, dispatch
// the clear command, and verify the protected response and counter advance.
static MunitResult
    test_secured_valid_command_protects_response(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    activate_ev2_session(emulator);

    uint8_t command[1 + DFC_WIRE_MAC_LENGTH] = {DFC_CMD_GET_KEY_SETTINGS};
    munit_assert_true(dfc_ev2_mac(
        emulator->ev2_session_mac_key,
        command[0],
        0,
        emulator->ev2_transaction_identifier,
        NULL,
        0,
        NULL,
        0,
        command + 1));

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x07;
    dfc_bytebuf_append_byte(&tx, prefix);
    munit_assert_true(
        dfc_emulator_handle_command_secured(emulator, command, sizeof(command), &tx, NULL));

    const uint8_t* response = dfc_bytebuf_get_data(&tx);
    const size_t response_len = dfc_bytebuf_get_size_bytes(&tx);
    munit_assert_size(response_len, >=, 1u + 1u + DFC_WIRE_MAC_LENGTH);
    munit_assert_uint8(response[0], ==, prefix);
    munit_assert_uint8(response[1], ==, DFC_STATUS_OK);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 1);

    const size_t response_data_len = response_len - 2u - DFC_WIRE_MAC_LENGTH;
    uint8_t expected_mac[DFC_WIRE_MAC_LENGTH];
    munit_assert_true(dfc_ev2_mac(
        emulator->ev2_session_mac_key,
        response[1],
        1,
        emulator->ev2_transaction_identifier,
        response + 2,
        response_data_len,
        NULL,
        0,
        expected_mac));
    munit_assert_memory_equal(
        sizeof(expected_mac), response + 2 + response_data_len, expected_mac);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult test_secured_response_allocation_failure_retires_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    activate_ev2_session(emulator);

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x04;
    dfc_bytebuf_append_byte(&tx, prefix);

    dfc_host_fail_next_allocation(DfcAllocByteBuf);
    const uint8_t select_picc[] = {DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x00};
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, select_picc, sizeof(select_picc), &tx, NULL));

    assert_plain_failure_after_prefix(&tx, prefix, DFC_STATUS_OUT_OF_EEPROM);
    munit_assert_false(emulator->ev2_session_active);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult test_secured_reassembly_allocation_failure_retires_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    activate_ev2_session(emulator);

    emulator->command_chain =
        dfc_platform_alloc(DFC_EMULATOR_CHAIN_BUFFER_SIZE, DfcAllocCommandChain);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain[0] = DFC_CMD_WRITE_DATA;
    emulator->command_chain_len = 1;
    emulator->command_chain_expected = 2;
    emulator->command_chain_active = true;

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x05;
    dfc_bytebuf_append_byte(&tx, prefix);

    dfc_host_fail_next_allocation(DfcAllocCommandChain);
    const uint8_t continuation[] = {DFC_CMD_ADDITIONAL_FRAME, 0x00};
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, continuation, sizeof(continuation), &tx, NULL));

    assert_plain_failure_after_prefix(&tx, prefix, DFC_STATUS_OUT_OF_EEPROM);
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_null(emulator->command_chain);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult test_secured_chain_allocation_failure_retires_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    make_ev3_8k_card(&credential);
    const uint8_t aid[] = {0xD1, 0xF2, 0x82};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    size_t app_index = dfc_credential_application_index(&credential, app);
    DfcFile* file = dfc_credential_create_file(&credential, app_index, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->comm_settings = DFC_COMM_ENCIPHERED;
    file->access_rights = 0x0000;
    munit_assert_true(dfc_file_resize(&credential, file, 32));

    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = app_index;
    activate_ev2_session(emulator);

    DfcByteBuf tx;
    dfc_bytebuf_reset(&tx);
    const uint8_t prefix = 0x06;
    dfc_bytebuf_append_byte(&tx, prefix);

    dfc_host_fail_next_allocation(DfcAllocCommandChain);
    const uint8_t first_frame[] = {
        DFC_CMD_WRITE_DATA,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
    };
    munit_assert_true(dfc_emulator_handle_command_secured(
        emulator, first_frame, sizeof(first_frame), &tx, NULL));

    assert_plain_failure_after_prefix(&tx, prefix, DFC_STATUS_OUT_OF_EEPROM);
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_null(emulator->command_chain);

    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/plain-getversion-preserves-prefix",
     test_secured_plain_getversion_preserves_prefix,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/getversion-wraps-to-iso7816-ev3-8k",
     test_secured_getversion_wraps_to_iso7816_ev3_8k,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/integrity-error-preserves-prefix",
     test_secured_integrity_error_preserves_prefix,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/valid-command-protects-response",
     test_secured_valid_command_protects_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/response-allocation-failure-retires-session",
     test_secured_response_allocation_failure_retires_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reassembly-allocation-failure-retires-session",
     test_secured_reassembly_allocation_failure_retires_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/chain-allocation-failure-retires-session",
     test_secured_chain_allocation_failure_retires_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_emulator_secured_envelope", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
