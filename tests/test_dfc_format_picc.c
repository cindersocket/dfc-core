#include "munit/munit.h"
#include "dfc_emulator_i.h"
#include "dfc_virtual_picc_test_helpers.h"

static const uint8_t format_picc[] = {0x90, 0xFC, 0x00, 0x00, 0x00};
static const uint8_t zero_key[16] = {0};
static const uint8_t key_one[16] =
    {0xC6, 0xEF, 0x84, 0x7C, 0xAE, 0x0A, 0x2A, 0x56, 0xC0, 0x19, 0x2A, 0xA1, 0xC4, 0xE8, 0xD9, 0xFB};

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    uint8_t response[64];
    size_t response_len;
} FormatFixture;

static void fixture_init(FormatFixture* fixture) {
    load_standard_credential(&fixture->credential);
    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
}

static void fixture_destroy(FormatFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}

static void select_format_app(FormatFixture* fixture, size_t app_index) {
    dfc_emulator_reset_session(fixture->session->emulator);
    fixture->session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    fixture->session->emulator->selected_app_index = app_index;
}

static void authenticate_legacy(FormatFixture* fixture, uint8_t key_no, const uint8_t* key) {
    authenticate_legacy_key(
        fixture->session,
        key_no,
        key,
        sizeof(zero_key),
        fixture->response,
        sizeof(fixture->response),
        &fixture->response_len,
        NULL,
        NULL,
        DFC_STATUS_OK);
}

static void expect_format_status(FormatFixture* fixture, uint8_t status) {
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->session,
            format_picc,
            sizeof(format_picc),
            fixture->response,
            sizeof(fixture->response),
            &fixture->response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(fixture->response_len, ==, 2);
    munit_assert_uint8(fixture->response[0], ==, 0x91);
    munit_assert_uint8(fixture->response[1], ==, status);
}

static void expect_format_with_data_status(FormatFixture* fixture, uint8_t status) {
    const uint8_t command[] = {0x90, 0xFC, 0x00, 0x00, 0x01, 0xAA, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->session,
            command,
            sizeof(command),
            fixture->response,
            sizeof(fixture->response),
            &fixture->response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(fixture->response_len, ==, 2);
    munit_assert_uint8(fixture->response[0], ==, 0x91);
    munit_assert_uint8(fixture->response[1], ==, status);
}

static void expect_credential_unchanged(const DfcCredential* before, const DfcCredential* after) {
    munit_assert_memory_equal(sizeof(*before), before, after);
}

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
static void begin_transaction_snapshot(FormatFixture* fixture, size_t app_index) {
    DfcEmulator* emulator = fixture->session->emulator;
    emulator->transaction_snapshot_pool_length = fixture->credential.file_pool_used;
    emulator->transaction_snapshot_pool_capacity = emulator->transaction_snapshot_pool_length;
    emulator->transaction_snapshot_pool =
        dfc_platform_alloc(emulator->transaction_snapshot_pool_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    memcpy(
        emulator->transaction_snapshot_pool,
        fixture->credential.file_pool,
        emulator->transaction_snapshot_pool_length);
    emulator->transaction_snapshot_active = true;
    emulator->transaction_snapshot_app_index = app_index;
    emulator->transaction_snapshot_dirty = false;
    fixture->credential.dirty = true;
}
#endif

static MunitResult test_disabled_picc_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    fixture_init(&fixture);
    fixture.credential.picc_format_disabled = true;
    authenticate_legacy(&fixture, 0, zero_key);
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_ILLEGAL_COMMAND_CODE);
    expect_credential_unchanged(&before, &fixture.credential);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_uint8(fixture.session->emulator->auth_key_no, ==, 0);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

static MunitResult test_picc_requires_master(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    fixture_init(&fixture);
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_AUTHENTICATION_ERR);
    expect_credential_unchanged(&before, &fixture.credential);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_picc_format_preserves_picc_record(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    fixture_init(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    uint8_t settings_1 = fixture.credential.picc_key_settings_1;
    uint8_t settings_2 = fixture.credential.picc_key_settings_2;
    size_t key_len = fixture.credential.picc_key_pool_len;
    uint8_t keys[DFC_MAX_KEY_LEN];
    munit_assert_size(key_len, <=, sizeof(keys));
    memcpy(keys, dfc_credential_key_const(&fixture.credential, NULL, 0), key_len);
    size_t old_file_pool_used = fixture.credential.file_pool_used;

    expect_format_status(&fixture, DFC_STATUS_OK);

    munit_assert_size(fixture.credential.num_apps, ==, 0);
    munit_assert_size(fixture.credential.num_files, ==, 0);
    munit_assert_size(fixture.credential.file_pool_used, ==, 0);
    for(size_t i = 0; i < old_file_pool_used; i++) {
        munit_assert_uint8(fixture.credential.file_pool[i], ==, 0);
    }
    munit_assert_uint8(fixture.credential.picc_key_settings_1, ==, settings_1);
    munit_assert_uint8(fixture.credential.picc_key_settings_2, ==, settings_2);
    munit_assert_size(fixture.credential.picc_key_pool_len, ==, key_len);
    munit_assert_memory_equal(
        key_len, keys, dfc_credential_key_const(&fixture.credential, NULL, 0));
    munit_assert_true(fixture.credential.dirty);
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
static MunitResult
    test_picc_format_aborts_transaction_first(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    fixture_init(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    size_t old_pool_used = fixture.credential.file_pool_used;
    begin_transaction_snapshot(&fixture, 0);

    expect_format_status(&fixture, DFC_STATUS_OK);

    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    munit_assert_null(fixture.session->emulator->transaction_snapshot_pool);
    munit_assert_true(fixture.credential.dirty);
    for(size_t i = 0; i < old_pool_used; i++) {
        munit_assert_uint8(fixture.credential.file_pool[i], ==, 0);
    }
    munit_assert_false(dfc_emulator_native_authentication_active(fixture.session->emulator));
    fixture_destroy(&fixture);
    return MUNIT_OK;
}
#endif

static void expect_ordinary_refusal(uint8_t auth_key_no, bool authenticate_first) {
    FormatFixture fixture;
    fixture_init(&fixture);
    select_format_app(&fixture, 0);
    if(authenticate_first) {
        authenticate_legacy(&fixture, auth_key_no, auth_key_no == 0 ? zero_key : key_one);
    }
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_PERMISSION_DENIED);
    expect_credential_unchanged(&before, &fixture.credential);
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(fixture.session->emulator->selected_app_index, ==, 0);
    fixture_destroy(&fixture);
}

static MunitResult
    test_ordinary_app_always_refuses(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    expect_ordinary_refusal(0, false);
    expect_ordinary_refusal(1, true);
    expect_ordinary_refusal(0, true);
    return MUNIT_OK;
}

static MunitResult
    test_invalid_application_selection_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    fixture_init(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    fixture.session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    fixture.session->emulator->selected_app_index = fixture.credential.num_apps;
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_PERMISSION_DENIED);
    expect_credential_unchanged(&before, &fixture.credential);
    munit_assert_size(fixture.credential.num_apps, >, 0);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

static MunitResult test_trailing_data_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;

    fixture_init(&fixture);
    DfcCredential picc_before = fixture.credential;
    expect_format_with_data_status(&fixture, DFC_STATUS_LENGTH_ERROR);
    expect_credential_unchanged(&picc_before, &fixture.credential);
    fixture_destroy(&fixture);

    fixture_init(&fixture);
    select_format_app(&fixture, 0);
    DfcCredential app_before = fixture.credential;
    expect_format_with_data_status(&fixture, DFC_STATUS_LENGTH_ERROR);
    expect_credential_unchanged(&app_before, &fixture.credential);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

#if DFC_ENABLE_DELEGATED_APPLICATIONS
static void add_other_app_and_file(FormatFixture* fixture) {
    const uint8_t aid[] = {0x11, 0x22, 0x33};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &fixture->credential, aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1);
    munit_assert_not_null(app);
    DfcFile* file = dfc_credential_create_file(&fixture->credential, 1, 0x22);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&fixture->credential, file, 4));
    memcpy(dfc_file_data(&fixture->credential, file), "KEEP", 4);
}

static void prepare_delegated_fixture(FormatFixture* fixture) {
    fixture_init(fixture);
    fixture->credential.apps[0].delegated = true;
    fixture->credential.apps[0].delegated_quota_limit = 64;
    fixture->credential.apps[0].delegated_free_blocks = 1;
#if DFC_ENABLE_TRANSACTION_MAC
    fixture->credential.files[0].type = DFC_FILE_TYPE_TRANSACTION_MAC;
    memset(
        fixture->credential.files[0].transaction_mac_key,
        0xA5,
        sizeof(fixture->credential.files[0].transaction_mac_key));
#endif
    add_other_app_and_file(fixture);
    select_format_app(fixture, 0);
}

static void expect_delegated_auth_refusal(uint8_t key_no, bool authenticate_first) {
    FormatFixture fixture;
    prepare_delegated_fixture(&fixture);
    if(authenticate_first) authenticate_legacy(&fixture, key_no, key_one);
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_AUTHENTICATION_ERR);
    expect_credential_unchanged(&before, &fixture.credential);
    fixture_destroy(&fixture);
}

static MunitResult
    test_delegated_requires_app_master(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    expect_delegated_auth_refusal(0, false);
    expect_delegated_auth_refusal(1, true);
    return MUNIT_OK;
}

static MunitResult
    test_delegated_format_is_scoped(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    prepare_delegated_fixture(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    DfcApplication target_before = fixture.credential.apps[0];
    target_before.delegated_free_blocks =
        target_before.delegated_quota_limit - DFC_APPLICATION_GENERAL_OVERHEAD_BLOCKS -
        DFC_DELEGATED_APPLICATION_OVERHEAD_BLOCKS - DFC_KEY_STORAGE_INDEX_BLOCKS - 1;
    DfcApplication other_before = fixture.credential.apps[1];
    size_t old_pool_used = fixture.credential.file_pool_used;

    expect_format_status(&fixture, DFC_STATUS_OK);

    munit_assert_size(fixture.credential.num_apps, ==, 2);
    munit_assert_memory_equal(sizeof(target_before), &target_before, &fixture.credential.apps[0]);
    munit_assert_memory_equal(sizeof(other_before), &other_before, &fixture.credential.apps[1]);
    munit_assert_size(dfc_credential_count_files_in_app(&fixture.credential, 0), ==, 0);
    munit_assert_size(dfc_credential_count_files_in_app(&fixture.credential, 1), ==, 1);
    DfcFile* survivor = dfc_credential_find_file_in_app(&fixture.credential, 1, 0x22);
    munit_assert_not_null(survivor);
    munit_assert_memory_equal(4, dfc_file_data(&fixture.credential, survivor), "KEEP");
    munit_assert_size(fixture.credential.file_pool_used, ==, 4);
    for(size_t i = fixture.credential.file_pool_used; i < old_pool_used; i++) {
        munit_assert_uint8(fixture.credential.file_pool[i], ==, 0);
    }
#if DFC_ENABLE_TRANSACTION_MAC
    const uint8_t* descriptors = (const uint8_t*)fixture.credential.files;
    size_t marker_run = 0;
    for(size_t i = 0; i < sizeof(fixture.credential.files); i++) {
        marker_run = descriptors[i] == 0xA5 ? marker_run + 1 : 0;
        munit_assert_size(marker_run, <, DFC_AES_KEY_LENGTH);
    }
#endif
    munit_assert_true(fixture.credential.dirty);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_int(
        fixture.session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(fixture.session->emulator->selected_app_index, ==, 0);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_delegated_disabled_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    prepare_delegated_fixture(&fixture);
    fixture.credential.apps[0].delegated_format_disabled = true;
    authenticate_legacy(&fixture, 0, zero_key);
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_status(&fixture, DFC_STATUS_PERMISSION_DENIED);

    expect_credential_unchanged(&before, &fixture.credential);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_delegated_trailing_data_preserves_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    prepare_delegated_fixture(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    dfc_credential_clear_dirty(&fixture.credential);
    DfcCredential before = fixture.credential;

    expect_format_with_data_status(&fixture, DFC_STATUS_LENGTH_ERROR);

    expect_credential_unchanged(&before, &fixture.credential);
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));
    munit_assert_uint8(fixture.session->emulator->auth_key_no, ==, 0);
    fixture_destroy(&fixture);
    return MUNIT_OK;
}

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
static MunitResult
    test_delegated_format_aborts_transaction_first(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    FormatFixture fixture;
    prepare_delegated_fixture(&fixture);
    authenticate_legacy(&fixture, 0, zero_key);
    DfcEmulator* emulator = fixture.session->emulator;
    begin_transaction_snapshot(&fixture, 0);

    expect_format_status(&fixture, DFC_STATUS_OK);

    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_true(fixture.credential.dirty);
    DfcFile* survivor = dfc_credential_find_file_in_app(&fixture.credential, 1, 0x22);
    munit_assert_not_null(survivor);
    munit_assert_memory_equal(4, dfc_file_data(&fixture.credential, survivor), "KEEP");
    munit_assert_true(dfc_emulator_native_authentication_active(emulator));
    fixture_destroy(&fixture);
    return MUNIT_OK;
}
#endif
#endif

static MunitTest tests[] = {
    {"/disabled-picc-is-atomic", test_disabled_picc_is_atomic, NULL, NULL, 0, NULL},
    {"/picc-requires-master", test_picc_requires_master, NULL, NULL, 0, NULL},
    {"/picc-format-preserves-picc-record",
     test_picc_format_preserves_picc_record,
     NULL,
     NULL,
     0,
     NULL},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    {"/picc-format-aborts-transaction-first",
     test_picc_format_aborts_transaction_first,
     NULL,
     NULL,
     0,
     NULL},
#endif
    {"/ordinary-app-always-refuses", test_ordinary_app_always_refuses, NULL, NULL, 0, NULL},
    {"/invalid-application-selection-is-atomic",
     test_invalid_application_selection_is_atomic,
     NULL,
     NULL,
     0,
     NULL},
    {"/trailing-data-is-atomic", test_trailing_data_is_atomic, NULL, NULL, 0, NULL},
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    {"/delegated-requires-app-master", test_delegated_requires_app_master, NULL, NULL, 0, NULL},
    {"/delegated-format-is-scoped", test_delegated_format_is_scoped, NULL, NULL, 0, NULL},
    {"/delegated-disabled-is-atomic", test_delegated_disabled_is_atomic, NULL, NULL, 0, NULL},
    {"/delegated-trailing-data-preserves-session",
     test_delegated_trailing_data_preserves_session,
     NULL,
     NULL,
     0,
     NULL},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    {"/delegated-format-aborts-transaction-first",
     test_delegated_format_aborts_transaction_first,
     NULL,
     NULL,
     0,
     NULL},
#endif
#endif
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_format_picc", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
