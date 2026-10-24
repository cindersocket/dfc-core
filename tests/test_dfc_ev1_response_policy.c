#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
#include "dfc_reader.h"

#include <stdio.h>
#include <string.h>

static void exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void expect_plain_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t status);

static void expect_protected_response(
    DfcVirtualPiccSession* session,
    DfcSecureMessaging* oracle,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected,
    size_t expected_len) {
    munit_assert_size(command_len, >=, 5);
    size_t body_len = command_len == 5 ? 0 : command[4];
    munit_assert_size(command_len, ==, body_len ? body_len + 6 : 5);
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(oracle, command[1], command + 5, body_len));

    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, command, command_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, >=, DFC_WIRE_MAC_LENGTH + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    uint8_t clear[128];
    size_t clear_len = dfc_secure_messaging_unwrap_ev1_response(
        oracle, DFC_STATUS_OK, response, response_len - 2, clear, sizeof(clear));
    munit_assert_size(clear_len, ==, expected_len);
    if(expected_len) munit_assert_int(memcmp(clear, expected, expected_len), ==, 0);
}

static void expect_full_command_protected_response(
    DfcVirtualPiccSession* session,
    DfcSecureMessaging* oracle,
    uint8_t instruction,
    const uint8_t* header,
    size_t header_len,
    const uint8_t* plain,
    size_t plain_len) {
    uint8_t crc_header[1 + DFC_READER_MAX_CLEAR_HEADER_LENGTH];
    munit_assert_size(header_len, <=, DFC_READER_MAX_CLEAR_HEADER_LENGTH);
    crc_header[0] = instruction;
    memcpy(crc_header + 1, header, header_len);

    uint8_t wrapped[64];
    size_t wrapped_len = dfc_secure_messaging_wrap(
        oracle,
        DFC_COMM_ENCIPHERED,
        crc_header,
        1 + header_len,
        plain,
        plain_len,
        wrapped,
        sizeof(wrapped));
    munit_assert_size(wrapped_len, >, 0);
    munit_assert_size(header_len + wrapped_len, <=, UINT8_MAX);

    uint8_t command[6 + sizeof(wrapped)];
    command[0] = DFC_ISO7816_CLA_WRAPPER;
    command[1] = instruction;
    command[2] = 0;
    command[3] = 0;
    command[4] = (uint8_t)(header_len + wrapped_len);
    memcpy(command + 5, header, header_len);
    memcpy(command + 5 + header_len, wrapped, wrapped_len);
    command[5 + header_len + wrapped_len] = 0;

    uint8_t response[128];
    size_t response_len = 0;
    exchange(
        session, command, 6 + header_len + wrapped_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, >=, DFC_WIRE_MAC_LENGTH + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

    uint8_t clear[128];
    size_t clear_len = dfc_secure_messaging_unwrap_ev1_response(
        oracle, DFC_STATUS_OK, response, response_len - 2, clear, sizeof(clear));
    munit_assert_size(clear_len, ==, 0);
    dfc_secure_wipe(wrapped, sizeof(wrapped));
    dfc_secure_wipe(clear, sizeof(clear));
}

static void expect_plain_special_response(
    DfcVirtualPiccSession* session,
    DfcSecureMessaging* oracle,
    const uint8_t* command,
    size_t command_len,
    uint8_t* payload,
    size_t payload_len) {
    size_t body_len = command_len == 5 ? 0 : command[4];
    munit_assert_size(command_len, ==, body_len ? body_len + 6 : 5);
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(oracle, command[1], command + 5, body_len));

    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, command, command_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, payload_len + 2);
    munit_assert_uint8(response[payload_len], ==, 0x91);
    munit_assert_uint8(response[payload_len + 1], ==, DFC_STATUS_SPECIAL_SUCCESS);
    if(payload_len && payload) memcpy(payload, response, payload_len);
}

static void expect_fixed_wire_response(
    DfcVirtualPiccSession* session,
    DfcSecureMessaging* oracle,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected_wire,
    size_t expected_wire_len) {
    size_t body_len = command_len == 5 ? 0 : command[4];
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(oracle, command[1], command + 5, body_len));
    uint8_t response[128];
    size_t response_len = 0;
    exchange(session, command, command_len, response, sizeof(response), &response_len);
    if(response_len != expected_wire_len || memcmp(response, expected_wire, response_len) != 0) {
        char actual[2 * sizeof(response) + 1] = {0};
        for(size_t index = 0; index < response_len; index++)
            snprintf(actual + 2 * index, 3, "%02X", response[index]);
        munit_errorf("wire response was %s", actual);
    }
}

typedef struct {
    const char* name;
    const uint8_t* command;
    size_t command_len;
    const uint8_t* expected;
    size_t expected_len;
} ProtectedCommandCase;

static DfcVirtualPiccSession* open_authenticated_application(
    DfcCredential* credential,
    DfcSecureMessaging** oracle,
    DfcApplication** app_out) {
    load_standard_credential(credential);
    DfcApplication* app = dfc_credential_get_primary_application(credential);
    munit_assert_not_null(app);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    exchange(session, select, sizeof(select), response, sizeof(response), &response_len);

    const uint8_t* key = dfc_credential_key_const(credential, app, 0);
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {0};
    authenticate_iso_key(
        session,
        0,
        key,
        app->key_len,
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);
    *oracle =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, session_key, session_key_len, NULL);
    munit_assert_not_null(*oracle);
    *app_out = app;
    return session;
}

static DfcVirtualPiccSession* open_authenticated_picc(
    DfcCredential* credential,
    DfcSecureMessaging** oracle,
    bool proximity_enabled) {
    dfc_credential_clear(credential);
    credential->card.generation = proximity_enabled ? DfcGenerationEv3 : DfcGenerationEv1;
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential->uid,
        ((const uint8_t[]){0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
        DFC_DESFIRE_UID_LEN);
    credential->picc_key_settings_1 = 0x0F;
    credential->picc_key_settings_2 = DFC_KEY_TYPE_DES_2K3DES | 1;
    credential->picc_auth_command = DFC_CMD_AUTHENTICATE_ISO;
    munit_assert_true(dfc_credential_keys_resize(credential, NULL, 1, 16));
#if DFC_ENABLE_PROXIMITY_CHECK
    if(proximity_enabled) {
        credential->picc_has_proximity_key = true;
        credential->picc_proximity_option = 0;
        credential->picc_proximity_published_response_time = 0x0102;
        for(size_t index = 0; index < sizeof(credential->picc_proximity_key); index++)
            credential->picc_proximity_key[index] = (uint8_t)(0x20 + index);
    }
#else
    (void)proximity_enabled;
#endif

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[128];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {0};
    authenticate_iso_key(
        session,
        0,
        dfc_credential_key_const(credential, NULL, 0),
        16,
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);
    *oracle =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, session_key, session_key_len, NULL);
    munit_assert_not_null(*oracle);
    return session;
}

static DfcSecureMessaging* install_known_ev1_session(DfcVirtualPiccSession* session) {
    const uint8_t key[DFC_AES_KEY_LENGTH] = {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F};
    session->emulator->secure_messaging =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    session->emulator->auth_key_no = 0;
    DfcSecureMessaging* oracle =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, key, sizeof(key), NULL);
    munit_assert_not_null(oracle);
    return oracle;
}

static MunitResult test_dispatcher_protects_every_ev1_success_response(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcApplication* app = NULL;
    DfcVirtualPiccSession* session = open_authenticated_application(&credential, &oracle, &app);

    const uint8_t change_settings_header[] = {0x0F};
    const uint8_t change_settings_data[] = {DFC_COMM_PLAIN, 0xEE, 0xEE};
    expect_full_command_protected_response(
        session,
        oracle,
        DFC_CMD_CHANGE_FILE_SETTINGS,
        change_settings_header,
        sizeof(change_settings_header),
        change_settings_data,
        sizeof(change_settings_data));
    const uint8_t create_linear[] = {
        0x90,
        DFC_CMD_CREATE_LINEAR_RECORD_FILE,
        0x00,
        0x00,
        0x0A,
        0x02,
        DFC_COMM_PLAIN,
        0xEE,
        0xEE,
        0x02,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00};
    const uint8_t create_cyclic[] = {
        0x90,
        DFC_CMD_CREATE_CYCLIC_RECORD_FILE,
        0x00,
        0x00,
        0x0A,
        0x03,
        DFC_COMM_PLAIN,
        0xEE,
        0xEE,
        0x02,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00};
    const uint8_t get_key_version[] = {
        0x90, DFC_CMD_GET_KEY_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00};

    uint8_t expected_version[] = {app->key_versions[0]};
    const ProtectedCommandCase cases[] = {
        {"CreateLinearRecordFile", create_linear, sizeof(create_linear), NULL, 0},
        {"CreateCyclicRecordFile", create_cyclic, sizeof(create_cyclic), NULL, 0},
        {"GetKeyVersion",
         get_key_version,
         sizeof(get_key_version),
         expected_version,
         sizeof(expected_version)},
    };
    for(size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        const ProtectedCommandCase* test_case = &cases[index];
        munit_logf(MUNIT_LOG_INFO, "checking %s", test_case->name);
        expect_protected_response(
            session,
            oracle,
            test_case->command,
            test_case->command_len,
            test_case->expected,
            test_case->expected_len);
    }

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_picc_directory_commands_chain_responses(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcVirtualPiccSession* session = open_authenticated_picc(&credential, &oracle, false);
    const uint8_t create_application[] = {
        0x90, DFC_CMD_CREATE_APPLICATION, 0, 0, 5, 1, 2, 3, 0x0F, 0x01, 0};
    const uint8_t get_application_ids[] = {0x90, DFC_CMD_GET_APPLICATION_IDS, 0, 0, 0};
    const uint8_t aid[] = {1, 2, 3};
    const ProtectedCommandCase cases[] = {
        {"CreateApplication", create_application, sizeof(create_application), NULL, 0},
        {"GetApplicationIds", get_application_ids, sizeof(get_application_ids), aid, sizeof(aid)},
    };
    for(size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        munit_logf(MUNIT_LOG_INFO, "checking %s", cases[index].name);
        expect_protected_response(
            session,
            oracle,
            cases[index].command,
            cases[index].command_len,
            cases[index].expected,
            cases[index].expected_len);
    }

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_fixed_wire_management_chains(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    dfc_credential_clear(&credential);
    credential.card.generation = DfcGenerationEv3;
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential.uid,
        ((const uint8_t[]){0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
        DFC_DESFIRE_UID_LEN);
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, DFC_AES_KEY_LENGTH));
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    DfcSecureMessaging* oracle = install_known_ev1_session(session);

    const uint8_t create_application[] = {
        0x90, DFC_CMD_CREATE_APPLICATION, 0, 0, 5, 1, 2, 3, 0x0F, 0x01, 0};
    const uint8_t get_application_ids[] = {0x90, DFC_CMD_GET_APPLICATION_IDS, 0, 0, 0};
    static const uint8_t create_response[] = {
        0x95, 0x9B, 0x71, 0x65, 0x82, 0xAE, 0xB2, 0xF2, 0x91, 0x00};
    static const uint8_t list_response[] = {
        0x01, 0x02, 0x03, 0x35, 0xC4, 0x7E, 0x2A, 0x5D, 0xE6, 0xEA, 0x99, 0x91, 0x00};
    expect_fixed_wire_response(
        session,
        oracle,
        create_application,
        sizeof(create_application),
        create_response,
        sizeof(create_response));
    expect_fixed_wire_response(
        session,
        oracle,
        get_application_ids,
        sizeof(get_application_ids),
        list_response,
        sizeof(list_response));

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);

    session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    oracle = install_known_ev1_session(session);
    const uint8_t get_card_uid[] = {0x90, DFC_CMD_GET_CARD_UID, 0, 0, 0};
    // Fixed AES-CBC result for the known session, including the command CMAC
    // state that supplies this response's IV.
    static const uint8_t uid_response[] = {
        0x5B,
        0x3D,
        0xEE,
        0x92,
        0x00,
        0xF4,
        0x97,
        0x4D,
        0x2E,
        0x4D,
        0x09,
        0x83,
        0x92,
        0x0C,
        0x31,
        0x18,
        0x91,
        0x00};
    expect_fixed_wire_response(
        session, oracle, get_card_uid, sizeof(get_card_uid), uid_response, sizeof(uid_response));
    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);

    load_standard_credential(&credential);
    session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[32];
    size_t response_len = 0;
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 0x4F, 0x49, 0xD3, 0};
    exchange(session, select, sizeof(select), response, sizeof(response), &response_len);
    oracle = install_known_ev1_session(session);
    const uint8_t create_linear[] = {
        0x90,
        DFC_CMD_CREATE_LINEAR_RECORD_FILE,
        0,
        0,
        10,
        2,
        DFC_COMM_PLAIN,
        0xEE,
        0xEE,
        2,
        0,
        0,
        3,
        0,
        0,
        0};
    const uint8_t create_cyclic[] = {
        0x90,
        DFC_CMD_CREATE_CYCLIC_RECORD_FILE,
        0,
        0,
        10,
        3,
        DFC_COMM_PLAIN,
        0xEE,
        0xEE,
        2,
        0,
        0,
        3,
        0,
        0,
        0};
    const uint8_t get_file_ids[] = {0x90, DFC_CMD_GET_FILE_IDS, 0, 0, 0};
    static const uint8_t linear_response[] = {
        0xC9, 0x39, 0x53, 0x45, 0xAB, 0x05, 0x8B, 0xEF, 0x91, 0x00};
    static const uint8_t cyclic_response[] = {
        0x2B, 0x0E, 0x06, 0x2C, 0x49, 0xBE, 0x8E, 0x82, 0x91, 0x00};
    static const uint8_t file_ids_response[] = {
        0x0F, 0x02, 0x03, 0x51, 0xD7, 0x15, 0x9C, 0x8E, 0xE4, 0x39, 0x6E, 0x91, 0x00};
    expect_fixed_wire_response(
        session,
        oracle,
        create_linear,
        sizeof(create_linear),
        linear_response,
        sizeof(linear_response));
    expect_fixed_wire_response(
        session,
        oracle,
        create_cyclic,
        sizeof(create_cyclic),
        cyclic_response,
        sizeof(cyclic_response));
    expect_fixed_wire_response(
        session,
        oracle,
        get_file_ids,
        sizeof(get_file_ids),
        file_ids_response,
        sizeof(file_ids_response));
    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_special_success_keeps_ev1_chain(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcApplication* app = NULL;
    DfcVirtualPiccSession* session = open_authenticated_application(&credential, &oracle, &app);
    credential.card.generation = DfcGenerationEv3;
    credential.picc_has_static_signature = true;
    for(size_t index = 0; index < sizeof(credential.picc_static_signature); index++)
        credential.picc_static_signature[index] = (uint8_t)(0x40 + index);

    const uint8_t read_signature[] = {0x90, DFC_CMD_READ_SIGNATURE, 0, 0, 1, 0, 0};
    uint8_t signature[DFC_STATIC_SIGNATURE_LENGTH];
    expect_plain_special_response(
        session, oracle, read_signature, sizeof(read_signature), signature, sizeof(signature));
    munit_assert_int(
        memcmp(signature, credential.picc_static_signature, sizeof(signature)), ==, 0);
    const uint8_t get_key_version[] = {0x90, DFC_CMD_GET_KEY_VERSION, 0, 0, 1, 0, 0};
    uint8_t expected_version[] = {app->key_versions[0]};
    expect_protected_response(
        session,
        oracle,
        get_key_version,
        sizeof(get_key_version),
        expected_version,
        sizeof(expected_version));

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

#if DFC_ENABLE_PROXIMITY_CHECK
static MunitResult
    test_proximity_successes_keep_ev1_chain(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcVirtualPiccSession* session = open_authenticated_picc(&credential, &oracle, true);

    const uint8_t prepare[] = {0x90, DFC_CMD_PREPARE_PROXIMITY_CHECK, 0, 0, 0};
    uint8_t published[1 + DFC_PROXIMITY_PUBLISHED_TIME_LENGTH];
    expect_plain_special_response(
        session, oracle, prepare, sizeof(prepare), published, sizeof(published));

    uint8_t proximity[5 + 1 + DFC_PROXIMITY_RANDOM_LENGTH + 1] = {
        0x90, DFC_CMD_PROXIMITY_CHECK, 0, 0, 1 + DFC_PROXIMITY_RANDOM_LENGTH};
    proximity[5] = DFC_PROXIMITY_RANDOM_LENGTH;
    for(size_t index = 0; index < DFC_PROXIMITY_RANDOM_LENGTH; index++)
        proximity[6 + index] = (uint8_t)(0x90 + index);
    uint8_t card_random[DFC_PROXIMITY_RANDOM_LENGTH];
    expect_plain_special_response(
        session, oracle, proximity, sizeof(proximity), card_random, sizeof(card_random));

    uint8_t transcript[DFC_PROXIMITY_TRANSCRIPT_MAX] = {0};
    memcpy(transcript, card_random, sizeof(card_random));
    memcpy(transcript + sizeof(card_random), proximity + 6, DFC_PROXIMITY_RANDOM_LENGTH);
    uint8_t verify[5 + DFC_WIRE_MAC_LENGTH + 1] = {
        0x90, DFC_CMD_VERIFY_PROXIMITY_CHECK, 0, 0, DFC_WIRE_MAC_LENGTH};
    munit_assert_true(dfc_reader_proximity_check_mac(
        credential.picc_proximity_key,
        false,
        published,
        sizeof(published),
        transcript,
        2 * DFC_PROXIMITY_RANDOM_LENGTH,
        verify + 5));
    uint8_t response_mac[DFC_WIRE_MAC_LENGTH];
    expect_plain_special_response(
        session, oracle, verify, sizeof(verify), response_mac, sizeof(response_mac));
    uint8_t expected_response_mac[DFC_WIRE_MAC_LENGTH];
    munit_assert_true(dfc_reader_proximity_check_mac(
        credential.picc_proximity_key,
        true,
        published,
        sizeof(published),
        transcript,
        2 * DFC_PROXIMITY_RANDOM_LENGTH,
        expected_response_mac));
    munit_assert_int(memcmp(response_mac, expected_response_mac, sizeof(response_mac)), ==, 0);

    const uint8_t get_application_ids[] = {0x90, DFC_CMD_GET_APPLICATION_IDS, 0, 0, 0};
    expect_protected_response(
        session, oracle, get_application_ids, sizeof(get_application_ids), NULL, 0);
    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_proximity_failure_retires_ev1_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcVirtualPiccSession* session = open_authenticated_picc(&credential, &oracle, true);
    const uint8_t prepare[] = {0x90, DFC_CMD_PREPARE_PROXIMITY_CHECK, 0, 0, 0};
    uint8_t published[1 + DFC_PROXIMITY_PUBLISHED_TIME_LENGTH];
    expect_plain_special_response(
        session, oracle, prepare, sizeof(prepare), published, sizeof(published));
    const uint8_t malformed[] = {0x90, DFC_CMD_PROXIMITY_CHECK, 0, 0, 1, 0, 0};
    expect_plain_status(session, malformed, sizeof(malformed), DFC_STATUS_LENGTH_ERROR);
    const uint8_t get_card_uid[] = {0x90, DFC_CMD_GET_CARD_UID, 0, 0, 0};
    expect_plain_status(
        session, get_card_uid, sizeof(get_card_uid), DFC_STATUS_AUTHENTICATION_ERR);
    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}
#endif

static void expect_plain_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t status) {
    uint8_t response[32];
    size_t response_len = 0;
    exchange(session, command, command_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, status);
}

static MunitResult test_session_retirement_precedes_response_policy(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 0x4F, 0x49, 0xD3, 0};
    const uint8_t delete_app[] = {0x90, DFC_CMD_DELETE_APPLICATION, 0, 0, 3, 0x4F, 0x49, 0xD3, 0};
    const uint8_t get_card_uid[] = {0x90, DFC_CMD_GET_CARD_UID, 0, 0, 0};
    const ProtectedCommandCase cases[] = {
        {"SelectApplication", select, sizeof(select), NULL, 0},
        {"DeleteApplication", delete_app, sizeof(delete_app), NULL, 0},
    };
    for(size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        DfcCredential credential;
        DfcSecureMessaging* oracle = NULL;
        DfcApplication* app = NULL;
        DfcVirtualPiccSession* session =
            open_authenticated_application(&credential, &oracle, &app);
        munit_logf(MUNIT_LOG_INFO, "checking %s", cases[index].name);
        expect_plain_status(
            session, cases[index].command, cases[index].command_len, DFC_STATUS_OK);
        expect_plain_status(
            session, get_card_uid, sizeof(get_card_uid), DFC_STATUS_AUTHENTICATION_ERR);
        dfc_secure_messaging_free(oracle);
        dfc_virtual_picc_session_free(session);
        (void)app;
    }

    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcVirtualPiccSession* session = open_authenticated_picc(&credential, &oracle, false);
    const uint8_t format_picc[] = {0x90, DFC_CMD_FORMAT_PICC, 0, 0, 0};
    expect_plain_status(session, format_picc, sizeof(format_picc), DFC_STATUS_OK);
    expect_plain_status(
        session, get_card_uid, sizeof(get_card_uid), DFC_STATUS_AUTHENTICATION_ERR);
    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_error_retires_session_without_response_mac(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcSecureMessaging* oracle = NULL;
    DfcApplication* app = NULL;
    DfcVirtualPiccSession* session = open_authenticated_application(&credential, &oracle, &app);

    const uint8_t unsupported[] = {0x90, 0xFE, 0, 0, 0};
    expect_plain_status(
        session, unsupported, sizeof(unsupported), DFC_STATUS_ILLEGAL_COMMAND_CODE);
    const uint8_t get_card_uid[] = {0x90, DFC_CMD_GET_CARD_UID, 0, 0, 0};
    expect_plain_status(
        session, get_card_uid, sizeof(get_card_uid), DFC_STATUS_AUTHENTICATION_ERR);

    dfc_secure_messaging_free(oracle);
    dfc_virtual_picc_session_free(session);
    (void)app;
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/dispatcher-protects-covered-ev1-success-responses",
     test_dispatcher_protects_every_ev1_success_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/special-success-keeps-ev1-chain",
     test_special_success_keeps_ev1_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_PROXIMITY_CHECK
    {"/proximity-successes-keep-ev1-chain",
     test_proximity_successes_keep_ev1_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/proximity-failure-retires-ev1-session",
     test_proximity_failure_retires_ev1_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/picc-directory-commands-chain-responses",
     test_picc_directory_commands_chain_responses,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/fixed-wire-management-chains",
     test_fixed_wire_management_chains,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/session-retirement-precedes-response-policy",
     test_session_retirement_precedes_response_policy,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/error-retires-session-without-response-mac",
     test_error_retires_session_without_response_mac,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite =
    {"/dfc_ev1_response_policy", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
