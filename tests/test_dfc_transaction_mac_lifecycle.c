#include "munit/munit.h"

#include <string.h>

#include "dfc_command.h"
#include "dfc_emulator_i.h"
#include "dfc_port_host.h"
#include "dfc_virtual_picc.h"

#if DFC_ENABLE_TRANSACTION_MAC

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
} LifecycleFixture;

static void exchange_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t expected) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, expected}));
}

static DfcFile*
    add_file(DfcCredential* credential, uint8_t number, uint8_t type, size_t length, uint8_t fill) {
    DfcFile* file = dfc_credential_create_file(credential, 0, number);
    munit_assert_not_null(file);
    file->type = type;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    if(type == DFC_FILE_TYPE_LINEAR_RECORD || type == DFC_FILE_TYPE_CYCLIC_RECORD) {
        file->record_size = 4;
        file->max_records = 3;
        file->record_count = 1;
    } else if(type == DFC_FILE_TYPE_VALUE) {
        file->value_lower_limit = 0;
        file->value_upper_limit = 100;
        file->value = 10;
        file->limited_credit = 1;
    }
    if(length) {
        munit_assert_true(dfc_file_resize(credential, file, length));
        memset(dfc_file_data(credential, file), fill, length);
    }
    return file;
}

static void add_transaction_mac_file(DfcCredential* credential) {
    DfcFile* file =
        add_file(credential, 5, DFC_FILE_TYPE_TRANSACTION_MAC, DFC_TRANSACTION_MAC_FILE_LENGTH, 0);
    file->contents_complete = true;
    memset(file->transaction_mac_key, 0x5A, sizeof(file->transaction_mac_key));
}

static void fixture_open(LifecycleFixture* fixture, bool with_transaction_mac) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    fixture->credential.card.storage = DfcStorage4KByteCount;
    fixture->credential.picc_has_static_signature = true;
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    const uint8_t aid[] = {1, 2, 3};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &fixture->credential, aid, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1));
    add_file(&fixture->credential, 1, DFC_FILE_TYPE_BACKUP_DATA, 8, 0x21);
    add_file(&fixture->credential, 2, DFC_FILE_TYPE_LINEAR_RECORD, 12, 0x32);
    add_file(&fixture->credential, 3, DFC_FILE_TYPE_CYCLIC_RECORD, 12, 0x43);
    add_file(&fixture->credential, 4, DFC_FILE_TYPE_VALUE, 0, 0);
    if(with_transaction_mac) add_transaction_mac_file(&fixture->credential);
    dfc_credential_clear_dirty(&fixture->credential);

    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 1, 2, 3, 0};
    exchange_status(fixture->session, select, sizeof(select), DFC_STATUS_OK);
}

static void fixture_close(LifecycleFixture* fixture) {
    dfc_virtual_picc_session_free(fixture->session);
}

static void open_pending(LifecycleFixture* fixture, const char* family) {
    if(strcmp(family, "backup") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_DATA, 0, 0, 11, 1, 0, 0, 0, 4, 0, 0, 0xB1, 0xB2, 0xB3, 0xB4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "linear") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 2, 0, 0, 0, 4, 0, 0, 0xC1, 0xC2, 0xC3, 0xC4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "cyclic") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {
            0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 3, 0, 0, 0, 4, 0, 0, 0xD1, 0xD2, 0xD3, 0xD4, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "value") == 0 || strcmp(family, "mixed") == 0) {
        const uint8_t command[] = {0x90, DFC_CMD_CREDIT, 0, 0, 5, 4, 5, 0, 0, 0, 0};
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
    }
    if(strcmp(family, "input") == 0 || strcmp(family, "mixed") == 0) {
        memset(fixture->session->emulator->transaction_input, 0xA5, 17);
        fixture->session->emulator->transaction_input_len = 17;
    }
}

typedef struct {
    bool dirty;
    uint8_t* snapshot_pool;
    size_t snapshot_length;
} PendingState;

static PendingState capture_pending_state(const LifecycleFixture* fixture) {
    return (PendingState){
        .dirty = fixture->credential.dirty,
        .snapshot_pool = fixture->session->emulator->transaction_snapshot_pool,
        .snapshot_length = fixture->session->emulator->transaction_snapshot_pool_length,
    };
}

static void assert_mixed_pending_unchanged(LifecycleFixture* fixture, PendingState before) {
    const DfcEmulator* emulator = fixture->session->emulator;
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture->credential, 0, 1);
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture->credential, 0, 2);
    DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture->credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture->credential, 0, 4);
    munit_assert_true(emulator->transaction_snapshot_active);
    munit_assert_ptr_equal(emulator->transaction_snapshot_pool, before.snapshot_pool);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, before.snapshot_length);
    munit_assert_int(fixture->credential.dirty, ==, before.dirty);
    munit_assert_true(backup->transaction_pending);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, backup),
        ((uint8_t[]){0xB1, 0xB2, 0xB3, 0xB4, 0x21, 0x21, 0x21, 0x21}));
    munit_assert_true(linear->transaction_pending);
    munit_assert_uint32(linear->record_count, ==, 2);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, linear),
        ((uint8_t[]){0x32, 0x32, 0x32, 0x32, 0xC1, 0xC2, 0xC3, 0xC4}));
    munit_assert_true(cyclic->transaction_pending);
    munit_assert_uint32(cyclic->record_count, ==, 2);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture->credential, cyclic),
        ((uint8_t[]){0x43, 0x43, 0x43, 0x43, 0xD1, 0xD2, 0xD3, 0xD4}));
    munit_assert_true(value->value_pending);
    munit_assert_int32(value->value_pending_delta, ==, 5);
    munit_assert_int32(value->value, ==, 10);
    munit_assert_size(emulator->transaction_input_len, ==, 17);
    for(size_t index = 0; index < 17; index++)
        munit_assert_uint8(emulator->transaction_input[index], ==, 0xA5);
}

static void assert_transaction_retired(LifecycleFixture* fixture, bool verify_abort_status) {
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture->credential, 0, 1);
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture->credential, 0, 2);
    DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture->credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture->credential, 0, 4);
    munit_assert_false(fixture->session->emulator->transaction_snapshot_active);
    munit_assert_null(fixture->session->emulator->transaction_snapshot_pool);
    munit_assert_false(backup->transaction_pending);
    munit_assert_false(linear->transaction_pending);
    munit_assert_false(cyclic->transaction_pending);
    munit_assert_false(value->value_pending);
    munit_assert_int32(value->value, ==, 10);
    munit_assert_size(fixture->session->emulator->transaction_input_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(fixture->session->emulator->transaction_input),
        fixture->session->emulator->transaction_input,
        ((uint8_t[sizeof(fixture->session->emulator->transaction_input)]){0}));
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture->credential, backup),
        ((uint8_t[]){0x21, 0x21, 0x21, 0x21}));
    munit_assert_uint32(linear->record_count, ==, 1);
    munit_assert_uint32(cyclic->record_count, ==, 1);
    if(verify_abort_status) {
        const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
        exchange_status(fixture->session, abort, sizeof(abort), DFC_STATUS_NO_CHANGES);
    }
}

static size_t build_create_transaction_mac(uint8_t file_number, uint8_t apdu[64]) {
    DfcCommand command;
    DfcCommandTransactionMacFile file = {
        .file_no = file_number,
        .comm_settings = DFC_COMM_PLAIN,
        .access_rights = 0xEFEE,
        .key_type = DFC_TRANSACTION_MAC_KEY_TYPE_AES,
        .key_version = 1,
    };
    memset(file.key, 0x5A, sizeof(file.key));
    munit_assert_int(dfc_command_create_transaction_mac_file(&command, &file), ==, DfcCommandOk);
    size_t apdu_len = 0;
    munit_assert_int(dfc_command_to_apdu(&command, apdu, 64, &apdu_len), ==, DfcCommandOk);
    return apdu_len;
}

static void create_transaction_mac(LifecycleFixture* fixture) {
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(5, apdu);
    exchange_status(fixture->session, apdu, apdu_len, DFC_STATUS_OK);
    DfcFile* file = dfc_credential_find_file_in_app(&fixture->credential, 0, 5);
    munit_assert_not_null(file);
    munit_assert_uint8(file->transaction_mac_key_type, ==, DFC_TRANSACTION_MAC_KEY_TYPE_AES);
}

static MunitResult test_lifecycle_retires_family(const MunitParameter params[], void* data) {
    (void)data;
    const char* lifecycle = munit_parameters_get(params, "lifecycle");
    const char* family = munit_parameters_get(params, "family");
    bool deleting = strcmp(lifecycle, "delete") == 0;
    LifecycleFixture fixture;
    fixture_open(&fixture, deleting);
    open_pending(&fixture, family);
    if(deleting) {
        const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
        exchange_status(fixture.session, command, sizeof(command), DFC_STATUS_OK);
        munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    } else {
        create_transaction_mac(&fixture);
        munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    }
    assert_transaction_retired(&fixture, true);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_retry_is_single_execution(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "mixed");
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    assert_transaction_retired(&fixture, false);
    /* Re-open pending input: replay must return the cached response without executing again. */
    memset(fixture.session->emulator->transaction_input, 0x6C, 7);
    fixture.session->emulator->transaction_input_len = 7;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(fixture.session->emulator->transaction_input_len, ==, 7);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_retry_rejects_different_command(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "backup");
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t different[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            different,
            sizeof(different),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_create_retry_is_single_execution(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    uint8_t command[64];
    size_t command_len = build_create_transaction_mac(5, command);
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    assert_transaction_retired(&fixture, false);
    memset(fixture.session->emulator->transaction_input, 0x6C, 7);
    fixture.session->emulator->transaction_input_len = 7;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(fixture.credential.num_files, ==, 5);
    munit_assert_size(fixture.session->emulator->transaction_input_len, ==, 7);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_create_retry_rejects_different_command(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    uint8_t command[64];
    size_t command_len = build_create_transaction_mac(5, command);
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, command_len, response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    const uint8_t different[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session,
            different,
            sizeof(different),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    munit_assert_size(fixture.credential.num_files, ==, 5);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_create_prevalidation(const MunitParameter params[], void* data) {
    (void)data;
    const char* failure = munit_parameters_get(params, "failure");
    bool existing_transaction_mac = strcmp(failure, "existing-transaction-mac") == 0;
    LifecycleFixture fixture;
    fixture_open(&fixture, existing_transaction_mac);
    open_pending(&fixture, "mixed");
    uint8_t file_number = strcmp(failure, "duplicate-number") == 0 ? 1 : 5;
    if(strcmp(failure, "invalid-number") == 0) file_number = DFC_EV1_MAX_FILE_NUMBER + 1;
    if(strcmp(failure, "file-count") == 0) {
        uint8_t next = 6;
        while(fixture.credential.num_files < DFC_MAX_FILES) {
            add_file(&fixture.credential, next++, DFC_FILE_TYPE_STANDARD_DATA, 0, 0);
        }
    }
    if(strcmp(failure, "pool-full") == 0) fixture.credential.file_pool_used = DFC_FILE_POOL_SIZE;
    if(strcmp(failure, "unauthorized") == 0) fixture.credential.apps[0].key_settings_1 = 0x0B;

    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    PendingState pending_before = capture_pending_state(&fixture);
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(file_number, apdu);
    uint8_t expected = DFC_STATUS_PARAMETER_ERROR;
    if(strcmp(failure, "malformed") == 0) {
        apdu[4]--;
        apdu_len -= 2;
    }
    if(strcmp(failure, "invalid-key-option") == 0) apdu[9] = DFC_KEY_TYPE_AES;
    if(strcmp(failure, "file-count") == 0) expected = DFC_STATUS_COUNT_ERROR;
    if(strcmp(failure, "pool-full") == 0) expected = DFC_STATUS_OUT_OF_EEPROM;
    if(strcmp(failure, "unauthorized") == 0) expected = DFC_STATUS_AUTHENTICATION_ERR;
    exchange_status(fixture.session, apdu, apdu_len, expected);
    munit_assert_size(fixture.credential.num_files, ==, files_before);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before);
    DfcFile* transaction_file = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_int(
        transaction_file && transaction_file->type == DFC_FILE_TYPE_TRANSACTION_MAC,
        ==,
        existing_transaction_mac);
    assert_mixed_pending_unchanged(&fixture, pending_before);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_delete_prevalidation(const MunitParameter params[], void* data) {
    (void)data;
    const char* failure = munit_parameters_get(params, "failure");
    LifecycleFixture fixture;
    fixture_open(&fixture, true);
    open_pending(&fixture, "mixed");
    uint8_t file_number = 6;
    uint8_t expected = DFC_STATUS_FILE_NOT_FOUND;
    bool preserves_transaction = false;
    if(strcmp(failure, "unauthorized-transaction-mac") == 0) {
        file_number = 5;
        fixture.credential.apps[0].key_settings_1 = 0x0B;
        expected = DFC_STATUS_AUTHENTICATION_ERR;
        preserves_transaction = true;
    } else if(strcmp(failure, "unauthorized-ordinary") == 0) {
        file_number = 1;
        fixture.credential.apps[0].key_settings_1 = 0x0B;
        expected = DFC_STATUS_AUTHENTICATION_ERR;
    }
    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    PendingState pending_before = capture_pending_state(&fixture);
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, file_number, 0};
    const uint8_t malformed[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 0};
    const uint8_t* request = command;
    size_t request_len = sizeof(command);
    if(strcmp(failure, "malformed") == 0) {
        request = malformed;
        request_len = sizeof(malformed);
        expected = DFC_STATUS_LENGTH_ERROR;
    }
    exchange_status(fixture.session, request, request_len, expected);
    munit_assert_size(fixture.credential.num_files, ==, files_before);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before);
    munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
    if(preserves_transaction)
        assert_mixed_pending_unchanged(&fixture, pending_before);
    else
        assert_transaction_retired(&fixture, true);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_transport_reuses_session_buffer(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    LifecycleFixture fixture;
    fixture_open(&fixture, false);
    open_pending(&fixture, "mixed");
    size_t files_before = fixture.credential.num_files;
    size_t pool_before = fixture.credential.file_pool_used;
    uint8_t apdu[64];
    size_t apdu_len = build_create_transaction_mac(5, apdu);
    uint8_t response[2];
    size_t response_len = 0;
    dfc_host_fail_next_allocation(DfcAllocEmulator);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, apdu, apdu_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(fixture.credential.num_files, ==, files_before + 1);
    DfcFile* created = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_not_null(created);
    munit_assert_size(fixture.credential.file_pool_used, ==, pool_before + created->data_len);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static char* lifecycle_values[] = {"create", "delete", NULL};
static char* family_values[] = {"backup", "linear", "cyclic", "value", "input", "mixed", NULL};
static MunitParameterEnum lifecycle_params[] = {
    {"lifecycle", lifecycle_values},
    {"family", family_values},
    {NULL, NULL},
};
static char* create_failure_values[] = {
    "malformed",
    "invalid-key-option",
    "existing-transaction-mac",
    "duplicate-number",
    "invalid-number",
    "file-count",
    "pool-full",
    "unauthorized",
    NULL,
};
static MunitParameterEnum create_failure_params[] = {
    {"failure", create_failure_values},
    {NULL, NULL},
};
static char* delete_failure_values[] = {
    "missing",
    "malformed",
    "unauthorized-ordinary",
    "unauthorized-transaction-mac",
    NULL,
};
static MunitParameterEnum delete_failure_params[] = {
    {"failure", delete_failure_values},
    {NULL, NULL},
};

static MunitTest tests[] = {
    {"/families",
     test_lifecycle_retires_family,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     lifecycle_params},
    {"/retry-once", test_retry_is_single_execution, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/retry-different",
     test_retry_rejects_different_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-retry-once",
     test_create_retry_is_single_execution,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-retry-different",
     test_create_retry_rejects_different_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-prevalidation",
     test_create_prevalidation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     create_failure_params},
    {"/delete-prevalidation",
     test_delete_prevalidation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     delete_failure_params},
    {"/transport-reuses-session-buffer",
     test_transport_reuses_session_buffer,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

#else

static MunitResult test_disabled_profile(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/disabled-profile", test_disabled_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

#endif

static const MunitSuite suite =
    {"/dfc_transaction_mac_lifecycle", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
