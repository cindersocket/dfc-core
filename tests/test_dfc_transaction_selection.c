#include "munit/munit.h"

#include <string.h>

#include "dfc_emulator_i.h"
#include "dfc_virtual_picc.h"

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    DfcFile* app0_backup;
    DfcFile* app0_records;
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
    file->record_size = 4;
    file->max_records = 3;
    file->record_count = 1;
    munit_assert_true(dfc_file_resize(credential, file, 12));
    memset(dfc_file_data(credential, file), 0, file->data_len);
    memset(dfc_file_data(credential, file), 0x11, file->record_size);
    file->contents_complete = true;
    return file;
}

static void fixture_open(SelectionFixture* fixture) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    fixture->credential.card.storage = DfcStorage4KByteCount;
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);

    add_application(&fixture->credential, App0Aid, App0IsoAid, 0xE101);
    add_application(&fixture->credential, App1Aid, App1IsoAid, 0xE102);
    fixture->app0_backup = add_backup_file(&fixture->credential, 0, 2, 0x22);
    fixture->app0_records = add_record_file(&fixture->credential, 0, 3);
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
    expect_native_status(fixture->session, write_backup, sizeof(write_backup), DFC_STATUS_OK);
    expect_native_status(fixture->session, write_record, sizeof(write_record), DFC_STATUS_OK);

    DfcEmulator* emulator = fixture->session->emulator;
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_size(emulator->transaction_snapshot_app_index, ==, 0);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    munit_assert_true(fixture->app0_backup->transaction_pending);
    munit_assert_true(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->record_count, ==, 2);
}

static void assert_transaction_rolled_back(SelectionFixture* fixture) {
    DfcEmulator* emulator = fixture->session->emulator;
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_false(fixture->app0_backup->transaction_pending);
    munit_assert_false(fixture->app0_records->transaction_pending);
    munit_assert_uint32(fixture->app0_records->record_count, ==, 1);
    munit_assert_memory_equal(
        4,
        dfc_file_data(&fixture->credential, fixture->app0_backup),
        ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    munit_assert_memory_equal(
        8,
        dfc_file_data(&fixture->credential, fixture->app0_records),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00}));
    munit_assert_false(fixture->credential.dirty);
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

static MunitTest tests[] = {
    {"/native", test_native_selection_aborts_transaction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/native-cross-app-allows-new-transaction",
     test_cross_app_selection_allows_new_transaction,
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
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_transaction_selection", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
