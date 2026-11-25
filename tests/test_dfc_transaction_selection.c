#include "munit/munit.h"

#include <string.h>

#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
#include "dfc_virtual_picc.h"

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    DfcFile* app0_backup;
    DfcFile* app0_records;
    DfcFile* app0_value;
    DfcFile* app0_standard;
    DfcFile* app1_backup;
} SelectionFixture;

static const uint8_t App0Aid[] = {0x01, 0x02, 0x03};
static const uint8_t App1Aid[] = {0x04, 0x05, 0x06};
static const uint8_t App0IsoAid[] = {0xA0, 0x00, 0x01};
static const uint8_t App1IsoAid[] = {0xA0, 0x00, 0x02};

static void expect_native_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected_status) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, expected_status);
}

static void expect_native_trailing_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected_status) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, expected_status);
}

static void
    expect_iso_ok(DfcVirtualPiccSession* session, const uint8_t* command, size_t command_len) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x90);
    munit_assert_uint8(response[1], ==, 0x00);
}

static DfcApplication* add_application(
    DfcCredential* credential,
    const uint8_t aid[3],
    const uint8_t iso_aid[3],
    uint16_t iso_file_id) {
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        credential, aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1);
    munit_assert_not_null(app);
    memcpy(app->iso_aid, iso_aid, 3);
    app->iso_aid_len = 3;
    app->has_iso_file_id = true;
    app->iso_file_id = iso_file_id;
    return app;
}

static DfcFile*
    add_backup_file(DfcCredential* credential, size_t app_index, uint8_t number, uint8_t fill) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_BACKUP_DATA;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    munit_assert_true(dfc_file_set_data_size(credential, file, 8));
    memset(dfc_file_data(credential, file), fill, file->data_len);
    return file;
}

static DfcFile* add_record_file(DfcCredential* credential, size_t app_index, uint8_t number) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->state.record.size = 4;
    file->state.record.max_records = 3;
    file->state.record.count = 1;
    munit_assert_true(dfc_file_resize(credential, file, 12));
    memset(dfc_file_data(credential, file), 0, file->data_len);
    memset(dfc_file_data(credential, file), 0x11, file->state.record.size);
    file->contents_complete = true;
    return file;
}

static DfcFile* add_value_file(DfcCredential* credential, size_t app_index, uint8_t number) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_VALUE;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->state.value.lower_limit = 0;
    file->state.value.upper_limit = 100;
    file->state.value.current = 10;
    return file;
}

static DfcFile* add_standard_file(DfcCredential* credential, size_t app_index, uint8_t number) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, number);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->has_iso_file_id = true;
    file->iso_file_id = 0xE103;
    munit_assert_true(dfc_file_set_data_size(credential, file, 8));
    memset(dfc_file_data(credential, file), 0x44, file->data_len);
    return file;
}

static void fixture_open(SelectionFixture* fixture) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    fixture->credential.picc_has_static_signature = true;
    fixture->credential.card.storage = DfcStorage4KByteCount;
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);

    add_application(&fixture->credential, App0Aid, App0IsoAid, 0xE101);
    add_application(&fixture->credential, App1Aid, App1IsoAid, 0xE102);
    fixture->app0_backup = add_backup_file(&fixture->credential, 0, 2, 0x22);
    fixture->app0_records = add_record_file(&fixture->credential, 0, 3);
    fixture->app0_value = add_value_file(&fixture->credential, 0, 4);
    fixture->app0_standard = add_standard_file(&fixture->credential, 0, 5);
    fixture->app1_backup = add_backup_file(&fixture->credential, 1, 2, 0x33);
    dfc_credential_clear_dirty(&fixture->credential);

    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t select_app0[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    expect_native_status(fixture->session, select_app0, sizeof(select_app0), DFC_STATUS_OK);
}

static void fixture_close(SelectionFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}

static void begin_transaction(SelectionFixture* fixture) {
    const uint8_t write_backup[] = {
        0x90,
        0x3D,
        0x00,
        0x00,
        0x0B,
        0x02,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0xB1,
        0xB1,
        0xB1,
        0xB1,
        0x00};
    const uint8_t write_record[] = {
        0x90,
        0x3B,
        0x00,
        0x00,
        0x0B,
        0x03,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0x00};
    const uint8_t credit_value[] = {
        0x90, DFC_CMD_CREDIT, 0x00, 0x00, 0x05, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00};
    expect_native_trailing_status(
        fixture->session, write_backup, sizeof(write_backup), DFC_STATUS_OK);
    expect_native_trailing_status(
        fixture->session, write_record, sizeof(write_record), DFC_STATUS_OK);
    expect_native_trailing_status(
        fixture->session, credit_value, sizeof(credit_value), DFC_STATUS_OK);

    DfcEmulator* emulator = fixture->session->emulator;
#if DFC_ENABLE_TRANSACTION_MAC
    memset(&emulator->transaction_mac, 0xD4, sizeof(emulator->transaction_mac));
    emulator->transaction_mac.initialized = true;
    emulator->transaction_mac.has_pending = true;
#endif
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_size(emulator->transaction_snapshot_app_index, ==, 0);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    munit_assert_true(fixture->app0_backup->transaction_pending);
    munit_assert_true(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->state.record.count, ==, 2);
    munit_assert_true(fixture->app0_value->state.value.pending);
    munit_assert_int32(fixture->app0_value->state.value.pending_delta, ==, 5);
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_true(emulator->transaction_mac.initialized);
    munit_assert_true(emulator->transaction_mac.has_pending);
#endif
}

static void
    assert_transaction_rolled_back_with_dirty(SelectionFixture* fixture, bool expected_dirty) {
    DfcEmulator* emulator = fixture->session->emulator;
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_false(fixture->app0_backup->transaction_pending);
    munit_assert_false(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->state.record.count, ==, 1);
    munit_assert_int32(fixture->app0_value->state.value.current, ==, 10);
    munit_assert_false(fixture->app0_value->state.value.pending);
    munit_assert_int32(fixture->app0_value->state.value.pending_delta, ==, 0);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture->credential, fixture->app0_backup),
        ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    munit_assert_memory_equal(
        8,
        dfc_file_data(&fixture->credential, fixture->app0_records),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00}));
    munit_assert_true(fixture->credential.dirty == expected_dirty);
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_memory_equal(
        sizeof(emulator->transaction_mac),
        &emulator->transaction_mac,
        &(DfcTransactionMacAccumulator){0});
#endif
}

static void assert_transaction_rolled_back(SelectionFixture* fixture) {
    assert_transaction_rolled_back_with_dirty(fixture, false);
}

static void assert_transaction_still_pending(SelectionFixture* fixture) {
    DfcEmulator* emulator = fixture->session->emulator;
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    munit_assert_true(fixture->app0_backup->transaction_pending);
    munit_assert_true(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->state.record.count, ==, 2);
    munit_assert_true(fixture->app0_value->state.value.pending);
    munit_assert_int32(fixture->app0_value->state.value.pending_delta, ==, 5);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture->credential, fixture->app0_backup),
        ((uint8_t[]){0xB1, 0xB1, 0xB1, 0xB1}));
    munit_assert_memory_equal(
        8,
        dfc_file_data(&fixture->credential, fixture->app0_records),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0xA1, 0xA2, 0xA3, 0xA4}));
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_true(emulator->transaction_mac.initialized);
    munit_assert_true(emulator->transaction_mac.has_pending);
#endif
}

static void abort_open_transaction(SelectionFixture* fixture) {
    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0x00, 0x00, 0x00};
    expect_native_status(fixture->session, abort, sizeof(abort), DFC_STATUS_OK);
    assert_transaction_rolled_back(fixture);
}

static void assert_app0_has_nothing_to_commit(SelectionFixture* fixture);

static MunitResult
    test_session_reset_aborts_complete_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    dfc_emulator_reset_session(fixture.session->emulator);
    assert_transaction_rolled_back(&fixture);
    assert_app0_has_nothing_to_commit(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static void finish_preserved_transaction(SelectionFixture* fixture, const char* finish) {
    bool commit = strcmp(finish, "commit") == 0;
    DfcApplication* app = &fixture->credential.apps[0];
    uint8_t installed_key[DFC_MAX_KEY_LEN];
    size_t key_len = dfc_emulator_key_len(fixture->session->emulator);
    memcpy(installed_key, dfc_credential_key_const(&fixture->credential, app, 0), key_len);
    uint8_t installed_version = app->key_versions[0];
    const uint8_t command[] = {
        0x90, commit ? DFC_CMD_COMMIT_TRANSACTION : DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    expect_native_trailing_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    munit_assert_memory_equal(
        key_len, dfc_credential_key_const(&fixture->credential, app, 0), installed_key);
    munit_assert_uint8(app->key_versions[0], ==, installed_version);
    munit_assert_true(fixture->credential.dirty);
    if(!commit) {
        assert_transaction_rolled_back_with_dirty(fixture, true);
        return;
    }
    munit_assert_false(fixture->session->emulator->transaction_snapshot_active);
    munit_assert_null(fixture->session->emulator->transaction_snapshot_pool);
    munit_assert_false(fixture->app0_backup->transaction_pending);
    munit_assert_false(fixture->app0_records->transaction_pending);
    munit_assert_false(fixture->app0_value->state.value.pending);
    munit_assert_int32(fixture->app0_value->state.value.current, ==, 15);
    munit_assert_uint32(fixture->app0_records->state.record.count, ==, 2);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture->credential, fixture->app0_backup),
        ((uint8_t[]){0xB1, 0xB1, 0xB1, 0xB1}));
    munit_assert_memory_equal(
        8,
        dfc_file_data(&fixture->credential, fixture->app0_records),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0xA1, 0xA2, 0xA3, 0xA4}));
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_memory_equal(
        sizeof(fixture->session->emulator->transaction_mac),
        &fixture->session->emulator->transaction_mac,
        &(DfcTransactionMacAccumulator){0});
#endif
}

static void select_standard_for_iso_update(SelectionFixture* fixture) {
    fixture->session->iso_file_selected = true;
    fixture->session->iso_file_index =
        (size_t)(fixture->app0_standard - fixture->credential.files);
}

static void assert_transaction_published(SelectionFixture* fixture) {
    DfcEmulator* emulator = fixture->session->emulator;
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_false(fixture->app0_backup->transaction_pending);
    munit_assert_false(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->state.record.count, ==, 2);
    munit_assert_false(fixture->app0_value->state.value.pending);
    munit_assert_int32(fixture->app0_value->state.value.pending_delta, ==, 0);
    munit_assert_int32(fixture->app0_value->state.value.current, ==, 15);
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_memory_equal(
        sizeof(emulator->transaction_mac),
        &emulator->transaction_mac,
        &(DfcTransactionMacAccumulator){0});
#endif
}

static MunitResult
    test_iso_update_publishes_complete_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    select_standard_for_iso_update(&fixture);

    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 1, 2, 0xA5, 0x5A};
    expect_iso_ok(fixture.session, update, sizeof(update));
    assert_transaction_published(&fixture);
    munit_assert_memory_equal(
        2, dfc_file_data(&fixture.credential, fixture.app0_standard) + 1, "\xA5\x5A");

    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    expect_native_status(fixture.session, abort, sizeof(abort), DFC_STATUS_NO_CHANGES);
    assert_transaction_published(&fixture);
    munit_assert_memory_equal(
        2, dfc_file_data(&fixture.credential, fixture.app0_standard) + 1, "\xA5\x5A");
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_iso_update_buffer_too_small_preserves_complete_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    select_standard_for_iso_update(&fixture);
    uint8_t response[2] = {0};
    size_t response_len = SIZE_MAX;

    // A failing ISO UPDATE BINARY discards the open transaction; that is measured on a genuine
    // card and replayed from hardware_physical_ev3_2k_iso_update_binary_transaction.vec.
    // What stays here is the part no vector can express: an answer that does not fit the
    // caller's buffer leaves the transaction pending until the exact retry succeeds.
    const uint8_t valid[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 1, 2, 0xA5, 0x5A};
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, valid, sizeof(valid), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    assert_transaction_still_pending(&fixture);
    munit_assert_memory_equal(
        2, dfc_file_data(&fixture.credential, fixture.app0_standard) + 1, "\x44\x44");

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, valid, sizeof(valid), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    assert_transaction_published(&fixture);
    munit_assert_memory_equal(
        2, dfc_file_data(&fixture.credential, fixture.app0_standard) + 1, "\xA5\x5A");

    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    expect_native_status(fixture.session, abort, sizeof(abort), DFC_STATUS_NO_CHANGES);
    assert_transaction_published(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_current_key_change_preserves_complete_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t old_key[16] = {0};
    static const uint8_t new_key[16] = {
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F};

    SelectionFixture fixture;
    fixture_open(&fixture);
    fixture.credential.apps[0].key_settings_2 = DFC_KEY_TYPE_AES | 1;
    fixture.credential.apps[0].has_auth_commands = false;
    uint8_t response[64];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[16];
    authenticate_aes_key(
        fixture.session,
        0,
        old_key,
        sizeof(old_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);
    begin_transaction(&fixture);
    memcpy(session_iv, fixture.session->emulator->secure_messaging->iv, sizeof(session_iv));

    uint8_t payload[49];
    size_t payload_len = build_ev1_change_key_payload(
        DFC_CMD_AUTHENTICATE_AES,
        session_key,
        session_key_len,
        session_iv,
        0,
        0,
        old_key,
        new_key,
        sizeof(new_key),
        true,
        0x42,
        payload);
    uint8_t change_key[5 + sizeof(payload) + 1] = {0x90, DFC_CMD_CHANGE_KEY, 0, 0};
    change_key[4] = (uint8_t)payload_len;
    memcpy(change_key + 5, payload, payload_len);
    change_key[5 + payload_len] = 0;
    if(strcmp(munit_parameters_get(params, "finish"), "invalid") == 0) {
        // Truncate the cryptogram so no new key material can be installed.
        change_key[4]--;
        // The truncated frame still ends with the Le byte the card requires.
        change_key[4 + payload_len] = 0;
        expect_native_status(
            fixture.session, change_key, 5 + payload_len, DFC_STATUS_LENGTH_ERROR);
        assert_transaction_rolled_back(&fixture);
        munit_assert_memory_equal(
            sizeof(old_key),
            dfc_credential_key_const(&fixture.credential, &fixture.credential.apps[0], 0),
            old_key);
        munit_assert_uint8(fixture.credential.apps[0].key_versions[0], ==, 0);
        fixture_close(&fixture);
        return MUNIT_OK;
    }
    expect_native_status(fixture.session, change_key, 6 + payload_len, DFC_STATUS_OK);

    assert_transaction_still_pending(&fixture);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_memory_equal(
        sizeof(new_key),
        dfc_credential_key_const(&fixture.credential, &fixture.credential.apps[0], 0),
        new_key);
    munit_assert_uint8(fixture.credential.apps[0].key_versions[0], ==, 0x42);
    authenticate_aes_key(
        fixture.session,
        0,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);
    assert_transaction_still_pending(&fixture);
    finish_preserved_transaction(&fixture, munit_parameters_get(params, "finish"));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_d40_current_key_change_preserves_complete_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t old_key[16] = {0};
    static const uint8_t new_key[16] = {
        0x10,
        0x32,
        0x54,
        0x76,
        0x98,
        0xBA,
        0xDC,
        0xFE,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF};

    SelectionFixture fixture;
    fixture_open(&fixture);
    uint8_t response[64];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    authenticate_legacy_key0(
        fixture.session,
        old_key,
        sizeof(old_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);
    begin_transaction(&fixture);

    uint8_t payload[1 + 24];
    size_t payload_len = build_legacy_change_key_payload(
        session_key, session_key_len, new_key, sizeof(new_key), 0x5A, payload);
    uint8_t change_key[5 + sizeof(payload) + 1] = {0x90, DFC_CMD_CHANGE_KEY, 0, 0};
    change_key[4] = (uint8_t)payload_len;
    memcpy(change_key + 5, payload, payload_len);
    change_key[5 + payload_len] = 0;
    if(strcmp(munit_parameters_get(params, "finish"), "invalid") == 0) {
        // Truncate the cryptogram so no new key material can be installed.
        change_key[4]--;
        // The truncated frame still ends with the Le byte the card requires.
        change_key[4 + payload_len] = 0;
        expect_native_status(
            fixture.session, change_key, 5 + payload_len, DFC_STATUS_LENGTH_ERROR);
        assert_transaction_rolled_back(&fixture);
        munit_assert_memory_equal(
            sizeof(old_key),
            dfc_credential_key_const(&fixture.credential, &fixture.credential.apps[0], 0),
            old_key);
        munit_assert_uint8(fixture.credential.apps[0].key_versions[0], ==, 0);
        fixture_close(&fixture);
        return MUNIT_OK;
    }
    expect_native_status(fixture.session, change_key, 6 + payload_len, DFC_STATUS_OK);

    assert_transaction_still_pending(&fixture);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    const uint8_t* stored_key =
        dfc_credential_key_const(&fixture.credential, &fixture.credential.apps[0], 0);
    for(size_t i = 0; i < sizeof(new_key); i++)
        munit_assert_uint8(stored_key[i] & 0xFE, ==, new_key[i] & 0xFE);
    munit_assert_uint8(fixture.credential.apps[0].key_versions[0], ==, 0x5A);
    authenticate_legacy_key0(
        fixture.session,
        stored_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        DFC_STATUS_OK);
    assert_transaction_still_pending(&fixture);
    finish_preserved_transaction(&fixture, munit_parameters_get(params, "finish"));
    fixture_close(&fixture);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING && DFC_ENABLE_KEY_SETS
static MunitResult test_ev2_current_key_change_preserves_complete_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t new_key[DFC_AES_KEY_LENGTH] = {
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F};

    SelectionFixture fixture;
    fixture_open(&fixture);
    DfcApplication* app = &fixture.credential.apps[0];
    app->key_settings_2 = DFC_KEY_TYPE_AES | 1;
    munit_assert_true(dfc_credential_keys_resize(&fixture.credential, app, 1, DFC_AES_KEY_LENGTH));
    begin_transaction(&fixture);

    DfcEmulator* emulator = fixture.session->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 0;
    uint8_t change_key[DFC_CHANGE_KEY_EV2_SAME_KEY_CLEAR_LENGTH] = {DFC_CMD_CHANGE_KEY_EV2, 0, 0};
    memcpy(change_key + DFC_CHANGE_KEY_EV2_HEADER_LENGTH, new_key, sizeof(new_key));
    change_key[DFC_CHANGE_KEY_EV2_HEADER_LENGTH + sizeof(new_key)] = 0x42;
    if(strcmp(munit_parameters_get(params, "finish"), "invalid") == 0) {
        dfc_bytebuf_reset(emulator->tx_buffer);
        munit_assert_true(dfc_emulator_handle_command(
            emulator, change_key, sizeof(change_key) - 1, emulator->tx_buffer, NULL));
        munit_assert_uint8(
            dfc_bytebuf_get_data(emulator->tx_buffer)[0], ==, DFC_STATUS_LENGTH_ERROR);
        assert_transaction_rolled_back(&fixture);
        munit_assert_memory_equal(
            sizeof(new_key),
            dfc_credential_key_const(&fixture.credential, app, 0),
            ((uint8_t[DFC_AES_KEY_LENGTH]){0}));
        munit_assert_uint8(app->key_versions[0], ==, 0);
        fixture_close(&fixture);
        return MUNIT_OK;
    }
    dfc_bytebuf_reset(emulator->tx_buffer);
    munit_assert_true(dfc_emulator_handle_command(
        emulator, change_key, sizeof(change_key), emulator->tx_buffer, NULL));
    munit_assert_size(dfc_bytebuf_get_size_bytes(emulator->tx_buffer), ==, 1);
    munit_assert_uint8(dfc_bytebuf_get_data(emulator->tx_buffer)[0], ==, DFC_STATUS_OK);

    assert_transaction_still_pending(&fixture);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_memory_equal(
        sizeof(new_key), dfc_credential_key_const(&fixture.credential, app, 0), new_key);
    munit_assert_uint8(app->key_versions[0], ==, 0x42);
    uint8_t response[64];
    size_t response_len = 0;
    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    uint8_t session_iv[16];
    authenticate_aes_key(
        fixture.session,
        0,
        new_key,
        sizeof(new_key),
        response,
        sizeof(response),
        &response_len,
        session_key,
        &session_key_len,
        session_iv,
        DFC_STATUS_OK);
    assert_transaction_still_pending(&fixture);
    finish_preserved_transaction(&fixture, munit_parameters_get(params, "finish"));
    fixture_close(&fixture);
    return MUNIT_OK;
}
#endif

static MunitResult
    test_terminal_native_errors_abort_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t missing_file[] = {
        0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x07, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    static const uint8_t malformed_read[] = {
        0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x01, 0x02, 0x00};
    static const uint8_t out_of_bounds[] = {
        0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x07, 0x02, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    static const uint8_t invalid_settings[] = {
        0x90,
        DFC_CMD_CHANGE_FILE_SETTINGS,
        0x00,
        0x00,
        0x04,
        0x02,
        DFC_COMM_PLAIN,
        0x4E,
        0xEE,
        0x00};
    static const uint8_t unknown_command[] = {0x90, 0xFF, 0x00, 0x00, 0x00};
    static const struct {
        const uint8_t* command;
        size_t length;
        uint8_t status;
    } cases[] = {
        {missing_file, sizeof(missing_file), DFC_STATUS_FILE_NOT_FOUND},
        {malformed_read, sizeof(malformed_read), DFC_STATUS_LENGTH_ERROR},
        {out_of_bounds, sizeof(out_of_bounds), DFC_STATUS_BOUNDARY_ERROR},
        {invalid_settings, sizeof(invalid_settings), DFC_STATUS_PARAMETER_ERROR},
        {unknown_command, sizeof(unknown_command), DFC_STATUS_ILLEGAL_COMMAND_CODE},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        SelectionFixture fixture;
        fixture_open(&fixture);
        begin_transaction(&fixture);
        expect_native_status(fixture.session, cases[i].command, cases[i].length, cases[i].status);
        assert_transaction_rolled_back(&fixture);
        assert_app0_has_nothing_to_commit(&fixture);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult
    test_interrupted_command_chain_aborts_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t first_write_frame[] = {
        0x90,
        DFC_CMD_WRITE_DATA,
        0x00,
        0x00,
        0x08,
        0x02,
        0x00,
        0x00,
        0x00,
        0x20,
        0x00,
        0x00,
        0xA5,
        0x00};
    const uint8_t interrupt[] = {
        0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    expect_native_status(
        fixture.session, first_write_frame, sizeof(first_write_frame), DFC_CMD_ADDITIONAL_FRAME);
    assert_transaction_still_pending(&fixture);
    expect_native_status(
        fixture.session, interrupt, sizeof(interrupt), DFC_STATUS_COMMAND_ABORTED);
    assert_transaction_rolled_back(&fixture);
    assert_app0_has_nothing_to_commit(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_success_and_additional_frame_keep_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t get_settings[] = {0x90, DFC_CMD_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, 0x02, 0x00};
    const uint8_t read_signature[] = {0x90, DFC_CMD_READ_SIGNATURE, 0x00, 0x00, 0x01, 0x00, 0x00};
    const uint8_t first_write_frame[] = {
        0x90,
        DFC_CMD_WRITE_DATA,
        0x00,
        0x00,
        0x08,
        0x02,
        0x00,
        0x00,
        0x00,
        0x20,
        0x00,
        0x00,
        0xA5,
        0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    expect_native_trailing_status(
        fixture.session, get_settings, sizeof(get_settings), DFC_STATUS_OK);
    assert_transaction_still_pending(&fixture);
    expect_native_trailing_status(
        fixture.session, read_signature, sizeof(read_signature), DFC_STATUS_SPECIAL_SUCCESS);
    assert_transaction_still_pending(&fixture);
    expect_native_status(
        fixture.session, first_write_frame, sizeof(first_write_frame), DFC_CMD_ADDITIONAL_FRAME);
    assert_transaction_still_pending(&fixture);
    dfc_emulator_discard_command_chain(fixture.session->emulator);
    abort_open_transaction(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

// A command the emulator does not answer must leave an open transaction exactly
// as it was. A bare AUTHENTICATE with no key number is such a command: the call
// reports "not handled" and writes no response. (A truncated SELECT APPLICATION
// used to be the example, but the card answers that one with a length error, so
// it now has an answer and is covered by the bad-commands physical vector.)
static MunitResult
    test_internal_no_response_keeps_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t truncated_authenticate[] = {DFC_CMD_AUTHENTICATE_LEGACY};

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    dfc_bytebuf_reset(fixture.session->emulator->tx_buffer);
    munit_assert_false(dfc_emulator_handle_command(
        fixture.session->emulator,
        truncated_authenticate,
        sizeof(truncated_authenticate),
        fixture.session->emulator->tx_buffer,
        NULL));
    munit_assert_size(dfc_bytebuf_get_size_bytes(fixture.session->emulator->tx_buffer), ==, 0);
    assert_transaction_still_pending(&fixture);
    abort_open_transaction(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_terminal_error_capacity_retry_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t missing_file[] = {
        0x90, DFC_CMD_READ_DATA, 0x00, 0x00, 0x07, 0x1E, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);

    uint8_t response[2] = {0xA5, 0xA5};
    size_t response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, missing_file, sizeof(missing_file), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(response[0], ==, 0xA5);
    assert_transaction_rolled_back(&fixture);

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            missing_file,
            sizeof(missing_file),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        response_len, response, ((uint8_t[]){0x91, DFC_STATUS_FILE_NOT_FOUND}));
    assert_transaction_rolled_back(&fixture);
    assert_app0_has_nothing_to_commit(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static void assert_app0_has_nothing_to_commit(SelectionFixture* fixture) {
    const uint8_t select_app0[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    const uint8_t commit[] = {0x90, 0xC7, 0x00, 0x00, 0x00};
    expect_native_status(fixture->session, select_app0, sizeof(select_app0), DFC_STATUS_OK);
    expect_native_status(fixture->session, commit, sizeof(commit), DFC_STATUS_NO_CHANGES);
}

static MunitResult
    test_native_selection_aborts_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t select_same[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    static const uint8_t select_other[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x00};
    static const uint8_t select_picc[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
    const struct {
        const uint8_t* command;
        size_t length;
    } cases[] = {
        {select_same, sizeof(select_same)},
        {select_other, sizeof(select_other)},
        {select_picc, sizeof(select_picc)},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        SelectionFixture fixture;
        fixture_open(&fixture);
        begin_transaction(&fixture);
        expect_native_status(fixture.session, cases[i].command, cases[i].length, DFC_STATUS_OK);
        assert_transaction_rolled_back(&fixture);
        assert_app0_has_nothing_to_commit(&fixture);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult
    test_cross_app_selection_allows_new_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t select_other[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x00};
    static const uint8_t write_other[] = {
        0x90,
        0x3D,
        0x00,
        0x00,
        0x0B,
        0x02,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0xC2,
        0xC2,
        0xC2,
        0xC2,
        0x00};
    static const uint8_t select_picc[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    expect_native_status(fixture.session, select_other, sizeof(select_other), DFC_STATUS_OK);
    assert_transaction_rolled_back(&fixture);

    expect_native_status(fixture.session, write_other, sizeof(write_other), DFC_STATUS_OK);
    munit_assert_true(fixture.session->emulator->transaction_snapshot_active);
    munit_assert_size(fixture.session->emulator->transaction_snapshot_app_index, ==, 1);
    munit_assert_true(fixture.app1_backup->transaction_pending);

    expect_native_status(fixture.session, select_picc, sizeof(select_picc), DFC_STATUS_OK);
    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    munit_assert_false(fixture.app1_backup->transaction_pending);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture.credential, fixture.app1_backup),
        ((uint8_t[]){0x33, 0x33, 0x33, 0x33}));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_delete_application_rolls_back_before_pool_compaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t zero_key[16] = {0};
    static const uint8_t delete_app0[] = {
        0x90, DFC_CMD_DELETE_APPLICATION, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    uint8_t response[64];
    size_t response_len = 0;
    authenticate_legacy_key0(
        fixture.session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);
    begin_transaction(&fixture);

    memset(response, 0xA5, sizeof(response));
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, delete_app0, sizeof(delete_app0), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(response[0], ==, 0xA5);
    munit_assert_size(fixture.credential.num_apps, ==, 1);
    munit_assert_size(fixture.credential.num_files, ==, 1);
    munit_assert_memory_equal(
        sizeof(App1Aid), fixture.credential.apps[0].aid, ((uint8_t[]){0x06, 0x05, 0x04}));
    munit_assert_size(fixture.credential.files[0].app_index, ==, 0);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture.credential, &fixture.credential.files[0]),
        ((uint8_t[]){0x33, 0x33, 0x33, 0x33}));
    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);
    munit_assert_size(fixture.session->emulator->selected_app_index, ==, 0);

    DfcCredential post_delete = fixture.credential;
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            delete_app0,
            sizeof(delete_app0),
            response,
            DFC_ISO7816_STATUS_WORD_LENGTH,
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(response_len, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_memory_equal(sizeof(post_delete), &fixture.credential, &post_delete);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_iso_selection_aborts_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t select_same_name[] = {
        0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x01, 0x00};
    static const uint8_t select_other_name[] = {
        0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x02, 0x00};
    static const uint8_t select_same_fid[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0xE1, 0x01, 0x00};
    static const uint8_t select_other_fid[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0xE1, 0x02, 0x00};
    static const uint8_t select_picc_name[] = {
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00};
    static const uint8_t select_picc_fid[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x00};
    const struct {
        const uint8_t* command;
        size_t length;
    } cases[] = {
        {select_same_name, sizeof(select_same_name)},
        {select_other_name, sizeof(select_other_name)},
        {select_same_fid, sizeof(select_same_fid)},
        {select_other_fid, sizeof(select_other_fid)},
        {select_picc_name, sizeof(select_picc_name)},
        {select_picc_fid, sizeof(select_picc_fid)},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        SelectionFixture fixture;
        fixture_open(&fixture);
        begin_transaction(&fixture);
        expect_iso_ok(fixture.session, cases[i].command, cases[i].length);
        assert_transaction_rolled_back(&fixture);
        assert_app0_has_nothing_to_commit(&fixture);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static void
    expect_shared_iso_ok(DfcEmulator* emulator, const uint8_t* command, size_t command_len) {
    bool app_selected = false;
    dfc_bytebuf_reset(emulator->tx_buffer);
    munit_assert_true(dfc_emulator_handle_iso7816_select(
        emulator, command, command_len, emulator->tx_buffer, 0, &app_selected));
    munit_assert_size(dfc_bytebuf_get_size_bytes(emulator->tx_buffer), ==, 2);
    const uint8_t* response = dfc_bytebuf_get_data(emulator->tx_buffer);
    munit_assert_uint8(response[0], ==, DFC_ISO7816_SW_OK_HI);
    munit_assert_uint8(response[1], ==, DFC_ISO7816_SW_OK_LO);
}

static MunitResult
    test_shared_iso_selection_aborts_transaction(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static const uint8_t select_same[] = {0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x01, 0x00};
    static const uint8_t select_other[] = {0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x02, 0x00};
    static const uint8_t select_picc[] = {
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00};
    const struct {
        const uint8_t* command;
        size_t length;
    } cases[] = {
        {select_same, sizeof(select_same)},
        {select_other, sizeof(select_other)},
        {select_picc, sizeof(select_picc)},
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        SelectionFixture fixture;
        fixture_open(&fixture);
        begin_transaction(&fixture);
        expect_shared_iso_ok(fixture.session->emulator, cases[i].command, cases[i].length);
        assert_transaction_rolled_back(&fixture);
        assert_app0_has_nothing_to_commit(&fixture);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult test_failed_shared_iso_selection_aborts_and_retains_selection(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t zero_key[16] = {0};
    static const uint8_t unknown_select[] = {0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x0F, 0x0F, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    uint8_t response[64];
    size_t response_len = 0;
    authenticate_legacy_key0(
        fixture.session,
        zero_key,
        sizeof(zero_key),
        response,
        sizeof(response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);
    begin_transaction(&fixture);

    bool app_selected = true;
    dfc_bytebuf_reset(fixture.session->emulator->tx_buffer);
    munit_assert_true(dfc_emulator_handle_iso7816_select(
        fixture.session->emulator,
        unknown_select,
        sizeof(unknown_select),
        fixture.session->emulator->tx_buffer,
        0,
        &app_selected));
    munit_assert_false(app_selected);
    munit_assert_memory_equal(
        2,
        dfc_bytebuf_get_data(fixture.session->emulator->tx_buffer),
        ((uint8_t[]){DFC_ISO7816_SW_NOT_FOUND_HI, DFC_ISO7816_SW_NOT_FOUND_LO}));
    assert_transaction_rolled_back(&fixture);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(fixture.session->emulator->selected_app_index, ==, 0);
    assert_app0_has_nothing_to_commit(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_host_failed_iso_selection_capacity_retry_is_atomic(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const uint8_t zero_key[16] = {0};
    static const uint8_t unknown_select[] = {0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x0F, 0x0F, 0x00};

    SelectionFixture fixture;
    fixture_open(&fixture);
    uint8_t auth_response[64];
    size_t response_len = 0;
    authenticate_legacy_key0(
        fixture.session,
        zero_key,
        sizeof(zero_key),
        auth_response,
        sizeof(auth_response),
        &response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);
    begin_transaction(&fixture);

    uint8_t response[2] = {0xA5, 0xA5};
    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, unknown_select, sizeof(unknown_select), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(response[0], ==, 0xA5);
    assert_transaction_still_pending(&fixture);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            unknown_select,
            sizeof(unknown_select),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        response_len,
        response,
        ((uint8_t[]){DFC_ISO7816_SW_NOT_FOUND_HI, DFC_ISO7816_SW_NOT_FOUND_LO}));
    assert_transaction_rolled_back(&fixture);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(fixture.session->emulator->selected_app_index, ==, 0);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_timer_expiry_rolls_back_transaction(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    SelectionFixture fixture;
    fixture_open(&fixture);
    DfcEmulator* emulator = fixture.session->emulator;
    begin_transaction(&fixture);
    dfc_emulator_advance_time(emulator, UINT32_MAX);
    assert_transaction_still_pending(&fixture);
    munit_assert_int(emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    emulator->transaction_timer_enabled = true;
    dfc_emulator_advance_time(emulator, DFC_TRANSACTION_TIMER_EXPIRY_MILLISECONDS - 1);
    assert_transaction_still_pending(&fixture);
    munit_assert_int(emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    dfc_emulator_advance_time(emulator, 1);
    assert_transaction_rolled_back(&fixture);
    munit_assert_int(emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);
    munit_assert_false(emulator->transaction_timer_enabled);
    munit_assert_uint32(emulator->transaction_timer_elapsed_milliseconds, ==, 0);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_timer_expiry_requires_reactivation(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    SelectionFixture fixture;
    fixture_open(&fixture);
    DfcVirtualPiccSession* session = fixture.session;
    DfcEmulator* emulator = session->emulator;
    DfcApplication* app = dfc_credential_get_application(&fixture.credential, 0);
    app->has_capability_data = true;
    app->capability_data[DFC_TRANSACTION_TIMER_CAPABILITY_OFFSET] = DFC_TRANSACTION_TIMER_SHORT;
    dfc_emulator_select_application(emulator, DfcEmulatorSelectedApplicationApp, 0);
    begin_transaction(&fixture);
    const uint8_t bad_command[] = {0x90, 0xFF, 0, 0, 0};
    expect_native_status(
        session, bad_command, sizeof(bad_command), DFC_STATUS_ILLEGAL_COMMAND_CODE);
    munit_assert_true(emulator->transaction_timer_enabled);
    munit_assert_uint32(emulator->transaction_timer_elapsed_milliseconds, ==, 0);
    begin_transaction(&fixture);
    emulator->awaiting_step2 = true;
    emulator->auth_key_no = 1;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    emulator->ev2_session_active = true;
    memset(emulator->ev2_session_mac_key, 0xA5, sizeof(emulator->ev2_session_mac_key));
#endif
    emulator->pending_chain_len = 3;
    memset(emulator->pending_chain, 0xA5, 3);
    session->iso_dep_selected = true;
    session->iso_dep_cid = 7;
    session->expected_pcd_sequence = 1;
    session->picc_sequence = 1;
    session->iso_file_selected = true;
    session->iso_file_index = 2;
    session->pending_command_len = 3;
    memset(session->pending_command, 0xA5, 3);
    session->pending_response_len = 3;
    memset(session->emulator->tx_buffer->data, 0xA5, 3);
    session->emulator->tx_buffer->size_bytes = 3;
    session->random_uid_valid = true;
    memset(session->random_uid, 0xA5, sizeof(session->random_uid));
    munit_assert_int(dfc_virtual_picc_advance_time(session, 999), ==, DfcVirtualPiccStatusOk);
    assert_transaction_still_pending(&fixture);
    munit_assert_true(session->activated);
    munit_assert_true(emulator->awaiting_step2);
    munit_assert_int(
        dfc_virtual_picc_advance_time(session, UINT32_MAX), ==, DfcVirtualPiccStatusOk);
    assert_transaction_rolled_back(&fixture);
    munit_assert_false(session->activated);
    munit_assert_false(session->iso_dep_selected);
    munit_assert_false(session->iso_file_selected);
    munit_assert_false(session->random_uid_valid);
    munit_assert_uint8(session->iso_dep_cid, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_uint8(session->picc_sequence, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 0);
    munit_assert_size(session->pending_response_len, ==, 0);
    munit_assert_false(emulator->awaiting_step2);
    munit_assert_size(emulator->pending_chain_len, ==, 0);
    munit_assert_uint8(emulator->auth_key_no, ==, 0);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_mac_key),
        emulator->ev2_session_mac_key,
        ((uint8_t[sizeof(emulator->ev2_session_mac_key)]){0}));
#endif
    const uint8_t select[] = {0x90, 0x5A, 0, 0, 3, 1, 2, 3, 0};
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select, sizeof(select), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusNoCard);
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusNoCard);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    expect_native_status(session, select, sizeof(select), DFC_STATUS_OK);
    munit_assert_true(emulator->transaction_timer_enabled);
    munit_assert_uint32(emulator->transaction_timer_elapsed_milliseconds, ==, 0);
    begin_transaction(&fixture);
    fixture_close(&fixture);
    return MUNIT_OK;
}
static char* finish_values[] = {"commit", "abort", "invalid", NULL};
static MunitParameterEnum finish_params[] = {{"finish", finish_values}, {NULL, NULL}};

static MunitTest tests[] = {
    {"/iso-update-publishes-complete-transaction",
     test_iso_update_publishes_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-update-buffer-too-small-preserves-complete-transaction",
     test_iso_update_buffer_too_small_preserves_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/timer-expiry-reactivation",
     test_timer_expiry_requires_reactivation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/timer-expiry-rollback",
     test_timer_expiry_rolls_back_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/session-reset-complete-rollback",
     test_session_reset_aborts_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/current-key-change-preserves-transaction",
     test_current_key_change_preserves_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     finish_params},
    {"/d40-current-key-change-preserves-transaction",
     test_d40_current_key_change_preserves_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     finish_params},
#if DFC_ENABLE_EV2_SECURE_MESSAGING && DFC_ENABLE_KEY_SETS
    {"/ev2-current-key-change-preserves-transaction",
     test_ev2_current_key_change_preserves_complete_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     finish_params},
#endif
    {"/terminal-native-errors",
     test_terminal_native_errors_abort_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/interrupted-command-chain",
     test_interrupted_command_chain_aborts_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/success-and-additional-frame",
     test_success_and_additional_frame_keep_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/internal-no-response",
     test_internal_no_response_keeps_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/terminal-error-capacity-retry",
     test_terminal_error_capacity_retry_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/native", test_native_selection_aborts_transaction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/native-cross-app-allows-new-transaction",
     test_cross_app_selection_allows_new_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/delete-before-pool-compaction",
     test_delete_application_rolls_back_before_pool_compaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso", test_iso_selection_aborts_transaction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/shared-iso",
     test_shared_iso_selection_aborts_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/shared-iso-not-found",
     test_failed_shared_iso_selection_aborts_and_retains_selection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/host-iso-not-found-capacity-retry",
     test_host_failed_iso_selection_capacity_retry_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_transaction_selection", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
