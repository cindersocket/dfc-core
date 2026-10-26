#include "munit/munit.h"
#include "dfc_emulator_i.h"
#include "dfc_ev2_crypto.h"
#include "dfc_virtual_picc_test_helpers.h"

enum {
    CounterFile = 0x0F,
    PendingValueFile = 0x10,
};

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    DfcFile* counter_file;
} CounterFixture;

static const uint8_t get_counters[] =
    {0x90, DFC_CMD_GET_FILE_COUNTERS, 0x00, 0x00, 0x01, CounterFile, 0x00};

static void fixture_open(CounterFixture* fixture, uint8_t file_type, bool sdm_enabled) {
    load_standard_credential(&fixture->credential);
    fixture->counter_file = &fixture->credential.files[0];
    fixture->counter_file->type = file_type;
    dfc_file_sdm_flag_set(fixture->counter_file, DfcSdmFlagEnabled, sdm_enabled);
    fixture->counter_file->state.data.sdm.access_rights = 0xEFFE;
    fixture->counter_file->state.data.sdm_read_counter = 0x563412;

    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    fixture->session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    fixture->session->emulator->selected_app_index = 0;
}

static void fixture_close(CounterFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}

static void exchange(
    CounterFixture* fixture,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->session, command, command_len, response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_status(
    CounterFixture* fixture,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected_status) {
    uint8_t response[64];
    size_t response_len = 0;
    exchange(fixture, command, command_len, response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((const uint8_t[]){0x91, expected_status}));
}

static void install_ev1_session(
    CounterFixture* fixture,
    uint8_t cipher,
    uint8_t key_no,
    const uint8_t* key,
    size_t key_len) {
    fixture->session->emulator->secure_messaging =
        dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    munit_assert_not_null(fixture->session->emulator->secure_messaging);
    fixture->session->emulator->auth_cipher = cipher;
    fixture->session->emulator->auth_key_no = key_no;
}

static DfcFile* add_pending_value_transaction(CounterFixture* fixture) {
    DfcFile* value = dfc_credential_create_file(&fixture->credential, 0, PendingValueFile);
    munit_assert_not_null(value);
    value->type = DFC_FILE_TYPE_VALUE;
    value->state.value.current = 20;
    value->state.value.pending = true;
    value->state.value.pending_delta = 7;
    return value;
}

static void assert_transaction_aborted(const DfcFile* value) {
    munit_assert_false(value->state.value.pending);
    munit_assert_int32(value->state.value.pending_delta, ==, 0);
    munit_assert_int32(value->state.value.current, ==, 20);
}

static size_t build_ev1_get_counters(
    DfcSecureMessaging* reader,
    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1]) {
    const uint8_t body[] = {CounterFile};
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        reader, DFC_CMD_GET_FILE_COUNTERS, body, sizeof(body)));

    const uint8_t prefix[] = {
        0x90,
        DFC_CMD_GET_FILE_COUNTERS,
        0x00,
        0x00,
        sizeof(body) + DFC_WIRE_MAC_LENGTH,
        CounterFile,
    };
    memcpy(command, prefix, sizeof(prefix));
    memcpy(command + sizeof(prefix), reader->iv, DFC_WIRE_MAC_LENGTH);
    command[sizeof(prefix) + DFC_WIRE_MAC_LENGTH] = 0x00;
    return sizeof(prefix) + DFC_WIRE_MAC_LENGTH + 1;
}

static void install_ev2_session(CounterFixture* fixture, uint8_t key_no) {
    DfcEmulator* emulator = fixture->session->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = key_no;
    emulator->ev2_command_counter = 4;
    for(size_t i = 0; i < sizeof(emulator->ev2_transaction_identifier); i++)
        emulator->ev2_transaction_identifier[i] = (uint8_t)(0x20 + i);
    for(size_t i = 0; i < sizeof(emulator->ev2_session_mac_key); i++)
        emulator->ev2_session_mac_key[i] = (uint8_t)(0x40 + i);
    for(size_t i = 0; i < sizeof(emulator->ev2_session_encryption_key); i++)
        emulator->ev2_session_encryption_key[i] = (uint8_t)(0x60 + i);
}

static void build_ev2_get_counters(
    const DfcEmulator* emulator,
    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1]) {
    const uint8_t prefix[] = {
        0x90,
        DFC_CMD_GET_FILE_COUNTERS,
        0x00,
        0x00,
        1 + DFC_WIRE_MAC_LENGTH,
        CounterFile,
    };
    memcpy(command, prefix, sizeof(prefix));
    munit_assert_true(dfc_ev2_mac(
        emulator->ev2_session_mac_key,
        DFC_CMD_GET_FILE_COUNTERS,
        emulator->ev2_command_counter,
        emulator->ev2_transaction_identifier,
        &command[5],
        1,
        NULL,
        0,
        &command[6]));
    command[6 + DFC_WIRE_MAC_LENGTH] = 0x00;
}

static MunitResult
    test_free_access_and_counter_boundaries(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    static const struct {
        uint32_t counter;
        uint8_t encoded[3];
    } cases[] = {
        {0x000000, {0x00, 0x00, 0x00}},
        {0x000001, {0x01, 0x00, 0x00}},
        {0xFFFFFE, {0xFE, 0xFF, 0xFF}},
        {0xFFFFFF, {0xFF, 0xFF, 0xFF}},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CounterFixture fixture;
        fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
        fixture.counter_file->state.data.sdm_read_counter = cases[i].counter;
        fixture.counter_file->state.data.sdm.access_rights = 0xEFFE;

        uint8_t response[16];
        size_t response_len = 0;
        exchange(
            &fixture,
            get_counters,
            sizeof(get_counters),
            response,
            sizeof(response),
            &response_len);
        munit_assert_size(response_len, ==, 7);
        munit_assert_memory_equal(3, response, cases[i].encoded);
        munit_assert_memory_equal(4, response + 3, ((const uint8_t[]){0, 0, 0x91, 0x00}));
        munit_assert_uint32(
            fixture.counter_file->state.data.sdm_read_counter, ==, cases[i].counter);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult
    test_target_and_access_statuses(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    static const struct {
        uint8_t file_type;
        bool sdm_enabled;
        uint8_t counter_access;
        uint8_t status;
    } cases[] = {
        {DFC_FILE_TYPE_VALUE, true, DFC_SDM_FREE_ACCESS, DFC_STATUS_PERMISSION_DENIED},
        {DFC_FILE_TYPE_STANDARD_DATA, false, DFC_SDM_FREE_ACCESS, DFC_STATUS_PERMISSION_DENIED},
        {DFC_FILE_TYPE_STANDARD_DATA, true, DFC_SDM_DENIED_ACCESS, DFC_STATUS_PERMISSION_DENIED},
        {DFC_FILE_TYPE_STANDARD_DATA, true, 1, DFC_STATUS_AUTHENTICATION_ERR},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CounterFixture fixture;
        fixture_open(&fixture, cases[i].file_type, cases[i].sdm_enabled);
        fixture.counter_file->state.data.sdm.access_rights =
            (uint16_t)(0xEFF0u | cases[i].counter_access);
        uint32_t counter_before = fixture.counter_file->state.data.sdm_read_counter;
        assert_status(&fixture, get_counters, sizeof(get_counters), cases[i].status);
        munit_assert_uint32(fixture.counter_file->state.data.sdm_read_counter, ==, counter_before);
        fixture_close(&fixture);
    }

    CounterFixture missing;
    fixture_open(&missing, DFC_FILE_TYPE_STANDARD_DATA, true);
    uint8_t command[sizeof(get_counters)];
    memcpy(command, get_counters, sizeof(command));
    command[5] = 0x1E;
    assert_status(&missing, command, sizeof(command), DFC_STATUS_FILE_NOT_FOUND);

    command[5] = (uint8_t)(CounterFile | 0x20u);
    assert_status(&missing, command, sizeof(command), DFC_STATUS_PARAMETER_ERROR);

    command[5] = (uint8_t)(CounterFile | 0x80u);
    assert_status(&missing, command, sizeof(command), DFC_STATUS_PERMISSION_DENIED);
    fixture_close(&missing);
    return MUNIT_OK;
}

static MunitResult
    test_malformed_command_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    DfcFile before = *fixture.counter_file;

    uint8_t short_command[] = {0x90, DFC_CMD_GET_FILE_COUNTERS, 0x00, 0x00, 0x00};
    assert_status(&fixture, short_command, sizeof(short_command), DFC_STATUS_LENGTH_ERROR);
    munit_assert_memory_equal(sizeof(before), fixture.counter_file, &before);

    uint8_t long_command[] = {
        0x90, DFC_CMD_GET_FILE_COUNTERS, 0x00, 0x00, 0x02, CounterFile, 0x00, 0x00};
    assert_status(&fixture, long_command, sizeof(long_command), DFC_STATUS_LENGTH_ERROR);
    munit_assert_memory_equal(sizeof(before), fixture.counter_file, &before);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_active_session_requires_full_response(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t session_key[24] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                     0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    static const struct {
        uint8_t cipher;
        size_t key_len;
        uint16_t access_rights;
        uint8_t key_no;
    } cases[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY, 8, 0xEFF1, 1},
        {DFC_CMD_AUTHENTICATE_ISO, 24, 0xEFF1, 1},
        {DFC_CMD_AUTHENTICATE_AES, 16, 0xEFF1, 1},
        {DFC_CMD_AUTHENTICATE_AES, 16, 0xEFFE, 0},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CounterFixture fixture;
        fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
        fixture.counter_file->state.data.sdm.access_rights = cases[i].access_rights;
        install_ev1_session(
            &fixture, cases[i].cipher, cases[i].key_no, session_key, cases[i].key_len);
        DfcSecureMessaging reader = *fixture.session->emulator->secure_messaging;
        reader.pcd = true;

        uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
        const uint8_t* transmitted = get_counters;
        size_t transmitted_len = sizeof(get_counters);
        if(cases[i].cipher != DFC_CMD_AUTHENTICATE_LEGACY) {
            transmitted_len = build_ev1_get_counters(&reader, command);
            transmitted = command;
        }

        uint8_t response[64];
        size_t response_len = 0;
        exchange(
            &fixture, transmitted, transmitted_len, response, sizeof(response), &response_len);
        munit_assert_size(response_len, >, 2);
        munit_assert_uint8(response[response_len - 2], ==, 0x91);
        munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);

        uint8_t clear[16];
        size_t clear_len = 0;
        munit_assert_true(dfc_secure_messaging_unwrap(
            &reader,
            DFC_COMM_ENCIPHERED,
            DFC_STATUS_OK,
            response,
            response_len - 2,
            clear,
            sizeof(clear),
            &clear_len));
        munit_assert_size(clear_len, ==, 5);
        munit_assert_memory_equal(5, clear, ((const uint8_t[]){0x12, 0x34, 0x56, 0x00, 0x00}));
        munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult
    test_ev1_requires_transmitted_command_mac(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t session_key[24] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                     0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    static const struct {
        uint8_t cipher;
        size_t key_len;
    } cases[] = {
        {DFC_CMD_AUTHENTICATE_ISO, 24},
        {DFC_CMD_AUTHENTICATE_AES, 16},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CounterFixture missing;
        fixture_open(&missing, DFC_FILE_TYPE_STANDARD_DATA, true);
        missing.counter_file->state.data.sdm.access_rights = 0xEFF1;
        DfcFile* missing_value = add_pending_value_transaction(&missing);
        install_ev1_session(&missing, cases[i].cipher, 1, session_key, cases[i].key_len);
        assert_status(&missing, get_counters, sizeof(get_counters), DFC_STATUS_INTEGRITY_ERROR);
        munit_assert_false(dfc_emulator_native_authentication_active(missing.session->emulator));
        munit_assert_uint32(missing.counter_file->state.data.sdm_read_counter, ==, 0x563412);
        assert_transaction_aborted(missing_value);
        fixture_close(&missing);

        CounterFixture bad;
        fixture_open(&bad, DFC_FILE_TYPE_STANDARD_DATA, true);
        bad.counter_file->state.data.sdm.access_rights = 0xEFF1;
        DfcFile* bad_value = add_pending_value_transaction(&bad);
        install_ev1_session(&bad, cases[i].cipher, 1, session_key, cases[i].key_len);
        DfcSecureMessaging reader = *bad.session->emulator->secure_messaging;
        reader.pcd = true;
        uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
        size_t command_len = build_ev1_get_counters(&reader, command);
        command[6] ^= 0x80;
        assert_status(&bad, command, command_len, DFC_STATUS_INTEGRITY_ERROR);
        munit_assert_false(dfc_emulator_native_authentication_active(bad.session->emulator));
        munit_assert_uint32(bad.counter_file->state.data.sdm_read_counter, ==, 0x563412);
        assert_transaction_aborted(bad_value);
        fixture_close(&bad);
    }
    return MUNIT_OK;
}

static MunitResult test_wrong_key_retires_session_and_aborts_transaction(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    fixture.counter_file->state.data.sdm.access_rights = 0xEFF1;
    fixture.counter_file->state.data.sdm_read_counter = 9;

    DfcFile* value = add_pending_value_transaction(&fixture);
    const uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    install_ev1_session(&fixture, DFC_CMD_AUTHENTICATE_AES, 0, session_key, sizeof(session_key));

    DfcSecureMessaging reader = *fixture.session->emulator->secure_messaging;
    reader.pcd = true;
    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
    size_t command_len = build_ev1_get_counters(&reader, command);

    assert_status(&fixture, command, command_len, DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_uint32(fixture.counter_file->state.data.sdm_read_counter, ==, 9);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    assert_transaction_aborted(value);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_d40_access_failure_retains_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    fixture.counter_file->state.data.sdm.access_rights = 0xEFF1;
    DfcFile* value = add_pending_value_transaction(&fixture);
    const uint8_t session_key[8] = {0};
    install_ev1_session(
        &fixture, DFC_CMD_AUTHENTICATE_LEGACY, 0, session_key, sizeof(session_key));

    assert_status(&fixture, get_counters, sizeof(get_counters), DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
    assert_transaction_aborted(value);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_command_mac_and_full_response(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    fixture.counter_file->state.data.sdm.access_rights = 0xEFF1;
    install_ev2_session(&fixture, 1);
    DfcEmulator before = *fixture.session->emulator;

    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
    build_ev2_get_counters(fixture.session->emulator, command);
    uint8_t response[64];
    size_t response_len = 0;
    exchange(&fixture, command, sizeof(command), response, sizeof(response), &response_len);

    munit_assert_size(response_len, ==, DFC_AES_KEY_LENGTH + DFC_WIRE_MAC_LENGTH + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_STATUS_OK);
    uint8_t expected_mac[DFC_WIRE_MAC_LENGTH];
    munit_assert_true(dfc_ev2_mac(
        before.ev2_session_mac_key,
        DFC_STATUS_OK,
        before.ev2_command_counter + 1,
        before.ev2_transaction_identifier,
        response,
        DFC_AES_KEY_LENGTH,
        NULL,
        0,
        expected_mac));
    munit_assert_memory_equal(sizeof(expected_mac), response + DFC_AES_KEY_LENGTH, expected_mac);

    uint8_t clear[DFC_AES_KEY_LENGTH];
    size_t clear_len = 0;
    munit_assert_true(dfc_ev2_decrypt_data(
        before.ev2_session_encryption_key,
        DfcEv2DirectionResponse,
        before.ev2_command_counter + 1,
        before.ev2_transaction_identifier,
        response,
        DFC_AES_KEY_LENGTH,
        clear,
        &clear_len,
        false));
    munit_assert_size(clear_len, ==, 5);
    munit_assert_memory_equal(5, clear, ((const uint8_t[]){0x12, 0x34, 0x56, 0x00, 0x00}));
    munit_assert_uint16(fixture.session->emulator->ev2_command_counter, ==, 5);
    munit_assert_true(fixture.session->emulator->ev2_session_active);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_bad_ev2_mac_returns_no_counter_data(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    fixture.counter_file->state.data.sdm.access_rights = 0xEFF1;
    fixture.counter_file->state.data.sdm_read_counter = 0x563412;
    DfcFile* value = add_pending_value_transaction(&fixture);

    install_ev2_session(&fixture, 1);
    DfcEmulator* emulator = fixture.session->emulator;
    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
    build_ev2_get_counters(emulator, command);
    command[6] ^= 0x80;

    assert_status(&fixture, command, sizeof(command), DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_uint32(fixture.counter_file->state.data.sdm_read_counter, ==, 0x563412);
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 0);
    assert_transaction_aborted(value);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_access_failure_retires_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    CounterFixture fixture;
    fixture_open(&fixture, DFC_FILE_TYPE_STANDARD_DATA, true);
    fixture.counter_file->state.data.sdm.access_rights = 0xEFF1;
    DfcFile* value = add_pending_value_transaction(&fixture);
    install_ev2_session(&fixture, 0);

    uint8_t command[6 + DFC_WIRE_MAC_LENGTH + 1];
    build_ev2_get_counters(fixture.session->emulator, command);
    assert_status(&fixture, command, sizeof(command), DFC_STATUS_AUTHENTICATION_ERR);
    munit_assert_false(fixture.session->emulator->ev2_session_active);
    assert_transaction_aborted(value);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/free-access-and-counter-boundaries",
     test_free_access_and_counter_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/target-and-access-statuses",
     test_target_and_access_statuses,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/malformed-command-is-atomic",
     test_malformed_command_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/active-session-requires-full-response",
     test_active_session_requires_full_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1-requires-transmitted-command-mac",
     test_ev1_requires_transmitted_command_mac,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/wrong-key-retires-session-and-aborts-transaction",
     test_wrong_key_retires_session_and_aborts_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/d40-access-failure-retains-session",
     test_d40_access_failure_retains_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-command-mac-and-full-response",
     test_ev2_command_mac_and_full_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/bad-ev2-mac-returns-no-counter-data",
     test_bad_ev2_mac_returns_no_counter_data,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-access-failure-retires-session",
     test_ev2_access_failure_retires_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_get_file_counters", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
