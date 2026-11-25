#include "munit/munit.h"

#include <string.h>

#include "dfc_command.h"
#include "dfc_emulator_i.h"
#include "dfc_port_host.h"
#include "dfc_virtual_picc.h"

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
} SnapshotFixture;

static void exchange_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t status) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, status);
}

static void exchange_tail_status(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t status) {
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, status);
}

static DfcFile* add_file(
    DfcCredential* credential,
    size_t app_index,
    uint8_t number,
    uint8_t type,
    size_t length,
    uint8_t fill) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, number);
    munit_assert_not_null(file);
    file->type = type;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    if(type == DFC_FILE_TYPE_LINEAR_RECORD) {
        file->state.record.size = 4;
        file->state.record.max_records = 3;
        file->state.record.count = 1;
    }
    if(type == DFC_FILE_TYPE_VALUE) {
        file->state.value.lower_limit = 0;
        file->state.value.upper_limit = 100;
        file->state.value.current = 10;
    }
    if(length) {
        munit_assert_true(dfc_file_resize(credential, file, length));
        memset(dfc_file_data(credential, file), fill, length);
    }
    return file;
}

static void fixture_open(SnapshotFixture* fixture) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    fixture->credential.card.storage = DfcStorage4KByteCount;
    fixture->credential.picc_has_static_signature = true;
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    const uint8_t app0[] = {1, 2, 3};
    const uint8_t app1[] = {4, 5, 6};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &fixture->credential, app0, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1));
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &fixture->credential, app1, 0x0F, DFC_KEY_TYPE_DES_2K3DES | 1));
    add_file(&fixture->credential, 0, 1, DFC_FILE_TYPE_STANDARD_DATA, 8, 0x10);
    add_file(&fixture->credential, 0, 2, DFC_FILE_TYPE_BACKUP_DATA, 8, 0x22);
    add_file(&fixture->credential, 0, 3, DFC_FILE_TYPE_LINEAR_RECORD, 12, 0x11);
    add_file(&fixture->credential, 0, 4, DFC_FILE_TYPE_VALUE, 0, 0);
    add_file(&fixture->credential, 1, 2, DFC_FILE_TYPE_BACKUP_DATA, 8, 0x33);
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

static void fixture_close(SnapshotFixture* fixture) {
    dfc_host_set_free_observer(NULL, NULL);
    dfc_virtual_picc_session_free(fixture->session);
}

static void begin_transaction(SnapshotFixture* fixture) {
    const uint8_t write_backup[] = {
        0x90, DFC_CMD_WRITE_DATA, 0, 0, 11, 2, 0, 0, 0, 4, 0, 0, 0xB1, 0xB1, 0xB1, 0xB1, 0};
    const uint8_t write_record[] = {
        0x90, DFC_CMD_WRITE_RECORD, 0, 0, 11, 3, 0, 0, 0, 4, 0, 0, 0xA1, 0xA2, 0xA3, 0xA4, 0};
    const uint8_t credit[] = {0x90, DFC_CMD_CREDIT, 0, 0, 5, 4, 5, 0, 0, 0, 0};
    exchange_status(fixture->session, write_backup, sizeof(write_backup), DFC_STATUS_OK);
    exchange_status(fixture->session, write_record, sizeof(write_record), DFC_STATUS_OK);
    exchange_status(fixture->session, credit, sizeof(credit), DFC_STATUS_OK);
#if DFC_ENABLE_TRANSACTION_MAC
    memset(
        &fixture->session->emulator->transaction_mac,
        0xD4,
        sizeof(fixture->session->emulator->transaction_mac));
    fixture->session->emulator->transaction_mac.initialized = true;
    fixture->session->emulator->transaction_mac.has_pending = true;
#endif
}

static void finish_transaction(SnapshotFixture* fixture, bool commit) {
    const uint8_t command[] = {
        0x90, commit ? DFC_CMD_COMMIT_TRANSACTION : DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
}

static void create_family(DfcVirtualPiccSession* session, const char* family, uint8_t file_number);
static void open_transaction_family(SnapshotFixture* fixture, const char* family);

static void create_standard_file(DfcVirtualPiccSession* session, uint8_t file_number) {
    const uint8_t command[] = {
        0x90,
        DFC_CMD_CREATE_STD_DATA_FILE,
        0,
        0,
        7,
        file_number,
        DFC_COMM_PLAIN,
        0xEE,
        0xEE,
        8,
        0,
        0,
        0,
    };
    exchange_status(session, command, sizeof(command), DFC_STATUS_OK);
}

static void write_data_status(
    DfcVirtualPiccSession* session,
    uint8_t file_number,
    uint32_t offset,
    const uint8_t* bytes,
    size_t length,
    uint8_t status) {
    uint8_t command[13 + 8] = {
        0x90,
        DFC_CMD_WRITE_DATA,
        0,
        0,
        (uint8_t)(7 + length),
        file_number,
        (uint8_t)offset,
        (uint8_t)(offset >> 8),
        (uint8_t)(offset >> 16),
        (uint8_t)length,
        (uint8_t)(length >> 8),
        (uint8_t)(length >> 16),
    };
    munit_assert_size(length, <=, 8);
    if(length) memcpy(command + 12, bytes, length);
    exchange_status(session, command, 13 + length, status);
}

static void open_transaction_family(SnapshotFixture* fixture, const char* family) {
    if(strcmp(family, "backup") == 0) {
        const uint8_t bytes[] = {0xB1, 0xB2, 0xB3, 0xB4};
        write_data_status(fixture->session, 2, 0, bytes, sizeof(bytes), DFC_STATUS_OK);
        return;
    }
    if(strcmp(family, "linear") == 0 || strcmp(family, "cyclic") == 0) {
        uint8_t file_number = 3;
        if(strcmp(family, "cyclic") == 0) {
            if(!dfc_credential_find_file_in_app(&fixture->credential, 0, 5)) {
                create_family(fixture->session, "cyclic", 5);
            }
            file_number = 5;
        }
        const uint8_t command[] = {
            0x90,
            DFC_CMD_WRITE_RECORD,
            0,
            0,
            11,
            file_number,
            0,
            0,
            0,
            4,
            0,
            0,
            0xA1,
            0xA2,
            0xA3,
            0xA4,
            0,
        };
        exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
        return;
    }
    munit_error("unknown transaction family");
}

static size_t build_create_family(
    const char* family,
    uint8_t file_number,
    uint8_t* apdu,
    size_t apdu_capacity) {
    DfcCommand command;
    if(strcmp(family, "standard") == 0 || strcmp(family, "backup") == 0) {
        DfcCommandDataFile file = {
            .file_no = file_number,
            .comm_settings = DFC_COMM_PLAIN,
            .access_rights = 0xEEEE,
            .size = 4,
        };
        DfcCommandStatus status = strcmp(family, "standard") == 0 ?
                                      dfc_command_create_standard_data_file(&command, &file) :
                                      dfc_command_create_backup_data_file(&command, &file);
        munit_assert_int(status, ==, DfcCommandOk);
    } else if(strcmp(family, "value") == 0) {
        DfcCommandValueFile file = {
            .file_no = file_number,
            .comm_settings = DFC_COMM_PLAIN,
            .access_rights = 0xEEEE,
            .lower_limit = 0,
            .upper_limit = 100,
            .value = 10,
            .limited_credit = 1,
        };
        munit_assert_int(dfc_command_create_value_file(&command, &file), ==, DfcCommandOk);
    } else if(strcmp(family, "linear") == 0 || strcmp(family, "cyclic") == 0) {
        DfcCommandRecordFile file = {
            .file_no = file_number,
            .comm_settings = DFC_COMM_PLAIN,
            .access_rights = 0xEEEE,
            .record_size = 4,
            .max_records = 3,
            .cyclic = strcmp(family, "cyclic") == 0,
        };
        munit_assert_int(dfc_command_create_record_file(&command, &file), ==, DfcCommandOk);
#if DFC_ENABLE_TRANSACTION_MAC
    } else if(strcmp(family, "transaction-mac") == 0) {
        DfcCommandTransactionMacFile file = {
            .file_no = file_number,
            .comm_settings = DFC_COMM_PLAIN,
            .access_rights = 0xEEEE,
            .key_type = DFC_KEY_TYPE_AES,
            .key_version = 1,
        };
        memset(file.key, 0x5A, sizeof(file.key));
        munit_assert_int(
            dfc_command_create_transaction_mac_file(&command, &file), ==, DfcCommandOk);
#endif
    } else {
        munit_error("unknown creation family");
    }
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_command_to_apdu(&command, apdu, apdu_capacity, &apdu_len), ==, DfcCommandOk);
    return apdu_len;
}

static void
    create_family(DfcVirtualPiccSession* session, const char* family, uint8_t file_number) {
    uint8_t apdu[DFC_COMMAND_MAX_DATA + 8];
    size_t apdu_len = build_create_family(family, file_number, apdu, sizeof(apdu));
    exchange_status(session, apdu, apdu_len, DFC_STATUS_OK);
}

static MunitResult test_create_publish_matrix(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const char* families[] = {"standard", "linear", "value"};
    for(size_t index = 0; index < sizeof(families) / sizeof(families[0]); index++) {
        uint8_t command[DFC_COMMAND_MAX_DATA + 8];
        size_t command_len = build_create_family(families[index], 5, command, sizeof(command));

        SnapshotFixture fixture;
        fixture_open(&fixture);
        begin_transaction(&fixture);
        dfc_credential_clear_dirty(&fixture.credential);
        size_t allocations = dfc_host_allocation_count(DfcAllocTransactionSnapshot);
        dfc_host_fail_next_allocation(DfcAllocTransactionSnapshot);
        exchange_status(fixture.session, command, command_len, DFC_STATUS_OK);
        munit_assert_not_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
        munit_assert_true(fixture.credential.dirty);
        munit_assert_size(dfc_host_allocation_count(DfcAllocTransactionSnapshot), ==, allocations);
        // File creation neither replaces nor grows the active journal.
        munit_assert_null(dfc_platform_alloc(1, DfcAllocTransactionSnapshot));
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static MunitResult
    test_journal_capacity_and_lazy_capture(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    size_t global_bytes = fixture.credential.file_pool_used;
    open_transaction_family(&fixture, "backup");
    DfcEmulator* emulator = fixture.session->emulator;
    munit_assert_size(emulator->transaction_snapshot_pool_capacity, ==, 20);
    munit_assert_size(emulator->transaction_snapshot_pool_capacity, <, global_bytes);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 8);

    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    size_t record_index = (size_t)(record - fixture.credential.files);
    const uint8_t* untouched_record = dfc_file_data_const(&fixture.credential, record);
    munit_assert_not_null(untouched_record);
    munit_assert_ptr_equal(
        dfc_emulator_transaction_snapshot_committed_data(emulator, record_index, NULL),
        untouched_record);
    munit_assert_size(
        dfc_emulator_transaction_snapshot_committed_record_count(emulator, record_index),
        ==,
        record->state.record.count);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 8);

    const uint8_t immediate[] = {0x71, 0x72, 0x73, 0x74};
    write_data_status(fixture.session, 1, 0, immediate, sizeof(immediate), DFC_STATUS_OK);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 8);

    open_transaction_family(&fixture, "linear");
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 20);
    finish_transaction(&fixture, false);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_memory_equal(
        sizeof(immediate), dfc_file_data_const(&fixture.credential, standard), immediate);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_journal_preserves_max_record_count(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    record->state.record.count = DFC_FILE_POOL_SIZE;
    open_transaction_family(&fixture, "backup");
    size_t record_index = (size_t)(record - fixture.credential.files);
    munit_assert_true(
        dfc_emulator_transaction_snapshot_capture_file(fixture.session->emulator, record_index));
    record->transaction_pending = true;
    record->state.record.count = 0;
    finish_transaction(&fixture, false);
    munit_assert_uint32(record->state.record.count, ==, DFC_FILE_POOL_SIZE);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_journal_preserves_full_configured_capacity(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
#if DFC_FILE_POOL_SIZE <= 4 * DFC_MAX_FILE_DATA
    SnapshotFixture fixture;
    fixture_open(&fixture);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    DfcFile* other_app = dfc_credential_find_file_in_app(&fixture.credential, 1, 2);
    munit_assert_true(dfc_file_resize(&fixture.credential, standard, 0));
    other_app = dfc_credential_find_file_in_app(&fixture.credential, 1, 2);
    munit_assert_true(dfc_file_resize(&fixture.credential, other_app, 0));
    const size_t quarter_pool = DFC_FILE_POOL_SIZE / 4;
    munit_assert_size(quarter_pool, <=, DFC_MAX_FILE_DATA);
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    munit_assert_true(dfc_file_resize(&fixture.credential, backup, quarter_pool));
    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    munit_assert_true(dfc_file_resize(&fixture.credential, record, quarter_pool));
    for(uint8_t number = 5; number <= 6; number++) {
        DfcFile* extra = add_file(
            &fixture.credential, 0, number, DFC_FILE_TYPE_BACKUP_DATA, quarter_pool, number);
        munit_assert_not_null(extra);
    }
    munit_assert_size(fixture.credential.file_pool_used, ==, DFC_FILE_POOL_SIZE);

    open_transaction_family(&fixture, "backup");
    munit_assert_size(
        fixture.session->emulator->transaction_snapshot_pool_capacity, ==, DFC_FILE_POOL_SIZE);
    open_transaction_family(&fixture, "linear");
    for(uint8_t number = 5; number <= 6; number++) {
        const uint8_t byte = number;
        write_data_status(fixture.session, number, 0, &byte, 1, DFC_STATUS_OK);
    }
    munit_assert_size(
        fixture.session->emulator->transaction_snapshot_pool_length, ==, DFC_FILE_POOL_SIZE);
    finish_transaction(&fixture, false);
    fixture_close(&fixture);
#endif
    return MUNIT_OK;
}

static void
    mutate_family(DfcVirtualPiccSession* session, const char* family, uint8_t file_number) {
    if(strcmp(family, "backup") == 0) {
        const uint8_t command[] = {
            0x90,
            DFC_CMD_WRITE_DATA,
            0,
            0,
            11,
            file_number,
            0,
            0,
            0,
            4,
            0,
            0,
            0xC1,
            0xC2,
            0xC3,
            0xC4,
            0};
        exchange_status(session, command, sizeof(command), DFC_STATUS_OK);
    } else if(strcmp(family, "value") == 0) {
        const uint8_t command[] = {0x90, DFC_CMD_CREDIT, 0, 0, 5, file_number, 5, 0, 0, 0, 0};
        exchange_status(session, command, sizeof(command), DFC_STATUS_OK);
    } else if(strcmp(family, "linear") == 0 || strcmp(family, "cyclic") == 0) {
        const uint8_t command[] = {
            0x90,
            DFC_CMD_WRITE_RECORD,
            0,
            0,
            11,
            file_number,
            0,
            0,
            0,
            4,
            0,
            0,
            0xD1,
            0xD2,
            0xD3,
            0xD4,
            0};
        exchange_status(session, command, sizeof(command), DFC_STATUS_OK);
    }
}

static MunitResult test_creation_family(const MunitParameter params[], void* data) {
    (void)data;
    const char* family = munit_parameters_get(params, "family");
    bool commit = strcmp(munit_parameters_get(params, "finish"), "commit") == 0;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    create_family(fixture.session, family, 5);
    mutate_family(fixture.session, family, 5);
    if(strcmp(family, "backup") == 0) {
        const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 5, 0, 0, 0, 4, 0, 0, 0};
        uint8_t response[8];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                fixture.session, read, sizeof(read), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 6);
        munit_assert_memory_equal(6, response, ((uint8_t[]){0, 0, 0, 0, 0x91, DFC_STATUS_OK}));
    }
    finish_transaction(&fixture, commit);
    munit_assert_true(fixture.credential.dirty);

    DfcFile* file = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_not_null(file);
    if(strcmp(family, "backup") == 0) {
        munit_assert_memory_equal(
            4,
            dfc_file_data_const(&fixture.credential, file),
            commit ? ((uint8_t[]){0xC1, 0xC2, 0xC3, 0xC4}) : ((uint8_t[]){0, 0, 0, 0}));
    } else if(strcmp(family, "value") == 0) {
        munit_assert_int32(file->state.value.current, ==, commit ? 15 : 10);
        munit_assert_false(file->state.value.pending);
    } else if(strcmp(family, "linear") == 0 || strcmp(family, "cyclic") == 0) {
        munit_assert_uint32(file->state.record.count, ==, commit ? 1 : 0);
        munit_assert_memory_equal(
            4,
            dfc_file_data_const(&fixture.credential, file),
            commit ? ((uint8_t[]){0xD1, 0xD2, 0xD3, 0xD4}) : ((uint8_t[]){0, 0, 0, 0}));
#if DFC_ENABLE_TRANSACTION_MAC
    } else if(!commit) {
        munit_assert_memory_equal(
            DFC_TRANSACTION_MAC_FILE_LENGTH,
            dfc_file_data_const(&fixture.credential, file),
            ((uint8_t[DFC_TRANSACTION_MAC_FILE_LENGTH]){0}));
#endif
    }
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_delete_rebases_pending_files(const MunitParameter params[], void* data) {
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    bool delete_lower = strcmp(munit_parameters_get(params, "delete"), "lower") == 0;
    bool commit = strcmp(munit_parameters_get(params, "finish"), "commit") == 0;
    uint8_t file_number = delete_lower ? 1 : 2;
    const uint8_t command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, file_number, 0};
    exchange_status(fixture.session, command, sizeof(command), DFC_STATUS_OK);
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture.credential, 0, 4);
    if(delete_lower) munit_assert_true(backup->transaction_pending);
    munit_assert_true(record->transaction_pending);
    munit_assert_true(value->state.value.pending);
    finish_transaction(&fixture, commit);
    munit_assert_true(fixture.credential.dirty);
    if(delete_lower) {
        munit_assert_memory_equal(
            4,
            dfc_file_data_const(&fixture.credential, backup),
            commit ? ((uint8_t[]){0xB1, 0xB1, 0xB1, 0xB1}) :
                     ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    } else {
        munit_assert_null(backup);
    }
    munit_assert_uint32(record->state.record.count, ==, commit ? 2 : 1);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, record),
        commit ? ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0xA1, 0xA2, 0xA3, 0xA4}) :
                 ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}));
    munit_assert_int32(value->state.value.current, ==, commit ? 15 : 10);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_mixed_and_cross_app_offsets(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    DfcFile* app1 = dfc_credential_find_file_in_app(&fixture.credential, 1, 2);
    size_t old_app1_offset = app1->data_offset;
    create_family(fixture.session, "backup", 5);
    const uint8_t delete_command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 1, 0};
    exchange_status(fixture.session, delete_command, sizeof(delete_command), DFC_STATUS_OK);
    create_family(fixture.session, "linear", 6);
    mutate_family(fixture.session, "backup", 5);
    mutate_family(fixture.session, "linear", 6);
    finish_transaction(&fixture, false);

    app1 = dfc_credential_find_file_in_app(&fixture.credential, 1, 2);
    munit_assert_size(app1->data_offset, ==, old_app1_offset - 8);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, app1),
        ((uint8_t[]){0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}));
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 6);
    munit_assert_memory_equal(
        4, dfc_file_data_const(&fixture.credential, backup), ((uint8_t[]){0, 0, 0, 0}));
    munit_assert_uint32(record->state.record.count, ==, 0);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_delete_and_recreate_same_number(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    const uint8_t delete_command[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 2, 0};
    exchange_status(fixture.session, delete_command, sizeof(delete_command), DFC_STATUS_OK);
    create_family(fixture.session, "backup", 2);
    mutate_family(fixture.session, "backup", 2);
    finish_transaction(&fixture, false);

    DfcFile* replacement = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    munit_assert_not_null(replacement);
    munit_assert_memory_equal(
        4, dfc_file_data_const(&fixture.credential, replacement), ((uint8_t[]){0, 0, 0, 0}));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_large_created_backup_read_streams_zeroes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
#if DFC_MAX_FILE_DATA >= 4096 && DFC_FILE_POOL_SIZE >= 8192
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    const uint8_t create[] = {
        0x90, DFC_CMD_CREATE_BACKUP_DATA_FILE, 0, 0, 7, 5, 0, 0xEE, 0xEE, 0, 0x10, 0, 0};
    exchange_status(fixture.session, create, sizeof(create), DFC_STATUS_OK);
    mutate_family(fixture.session, "backup", 5);

    const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 5, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t additional_frame[] = {0x90, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 0};
    const uint8_t* command = read;
    size_t command_len = sizeof(read);
    size_t received = 0;
    for(;;) {
        uint8_t response[DFC_EV3_MAX_RESPONSE_PAYLOAD + 2];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                fixture.session, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, >=, 2);
        for(size_t index = 0; index + 2 < response_len; index++)
            munit_assert_uint8(response[index], ==, 0);
        received += response_len - 2;
        if(response[response_len - 1] == DFC_STATUS_OK) break;
        munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
        command = additional_frame;
        command_len = sizeof(additional_frame);
    }
    munit_assert_size(received, ==, 4096);
    fixture_close(&fixture);
#endif
    return MUNIT_OK;
}

static MunitResult test_retry_executes_once(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    const uint8_t create[] = {
        0x90, DFC_CMD_CREATE_BACKUP_DATA_FILE, 0, 0, 7, 5, 0, 0xEE, 0xEE, 4, 0, 0, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, create, sizeof(create), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(dfc_credential_count_files_in_app(&fixture.credential, 0), ==, 5);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, create, sizeof(create), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_size(dfc_credential_count_files_in_app(&fixture.credential, 0), ==, 5);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_journal_allocation_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    dfc_host_fail_next_allocation(DfcAllocTransactionSnapshot);
    const uint8_t replacement[] = {0xB1, 0xB2, 0xB3, 0xB4};
    write_data_status(
        fixture.session, 2, 0, replacement, sizeof(replacement), DFC_STATUS_PERMISSION_DENIED);
    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    DfcFile* record = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture.credential, 0, 4);
    munit_assert_false(backup->transaction_pending);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, backup),
        ((uint8_t[]){0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}));
    munit_assert_false(record->transaction_pending);
    munit_assert_uint32(record->state.record.count, ==, 1);
    munit_assert_memory_equal(
        12,
        dfc_file_data_const(&fixture.credential, record),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}));
    munit_assert_false(value->state.value.pending);
    munit_assert_int32(value->state.value.current, ==, 10);
    munit_assert_false(fixture.credential.dirty);
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_memory_equal(
        sizeof(fixture.session->emulator->transaction_mac),
        &fixture.session->emulator->transaction_mac,
        &(DfcTransactionMacAccumulator){0});
#endif
    fixture_close(&fixture);
    return MUNIT_OK;
}

typedef struct {
    const void* target;
    size_t length;
    bool observed;
    bool zeroed;
} WipeAudit;

static void observe_wipe(const void* ptr, void* context) {
    WipeAudit* audit = context;
    if(ptr != audit->target) return;
    audit->observed = true;
    audit->zeroed = true;
    const uint8_t* bytes = ptr;
    for(size_t index = 0; index < audit->length; index++) {
        if(bytes[index] != 0) audit->zeroed = false;
    }
}

static MunitResult
    test_journal_is_not_reallocated_and_is_fully_wiped(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    DfcEmulator* emulator = fixture.session->emulator;
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 20);
    WipeAudit audit = {
        .target = emulator->transaction_snapshot_pool,
        .length = emulator->transaction_snapshot_pool_capacity,
    };
    dfc_host_set_free_observer(observe_wipe, &audit);
    create_family(fixture.session, "backup", 5);
    size_t old_length = emulator->transaction_snapshot_pool_length;
    const uint8_t remove[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    exchange_status(fixture.session, remove, sizeof(remove), DFC_STATUS_OK);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, old_length);
    munit_assert_false(audit.observed);
    finish_transaction(&fixture, false);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.observed);
    munit_assert_true(audit.zeroed);
    munit_assert_memory_equal(
        sizeof(emulator->transaction_snapshot_offsets),
        emulator->transaction_snapshot_offsets,
        ((uint32_t[DFC_MAX_FILES]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->transaction_snapshot_captured),
        emulator->transaction_snapshot_captured,
        ((uint8_t[DFC_TRANSACTION_FILE_BITMAP_SIZE]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->transaction_snapshot_created),
        emulator->transaction_snapshot_created,
        ((uint8_t[DFC_TRANSACTION_FILE_BITMAP_SIZE]){0}));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_immediate_write_survives_abort(const MunitParameter params[], void* data) {
    (void)data;
    const char* family = munit_parameters_get(params, "family");
    bool after = strcmp(munit_parameters_get(params, "position"), "after") == 0;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    uint8_t file_number = 1;
    if(after) {
        if(strcmp(family, "cyclic") == 0) create_family(fixture.session, "cyclic", 5);
        create_standard_file(fixture.session, 6);
        file_number = 6;
    }
    dfc_credential_clear_dirty(&fixture.credential);
    open_transaction_family(&fixture, family);
    const uint8_t replacement[] = {0x61, 0x62, 0x63, 0x64};
    write_data_status(
        fixture.session, file_number, 2, replacement, sizeof(replacement), DFC_STATUS_OK);
    finish_transaction(&fixture, false);

    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, file_number);
    munit_assert_memory_equal(
        sizeof(replacement), dfc_file_data_const(&fixture.credential, standard) + 2, replacement);
    munit_assert_true(fixture.credential.dirty);
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, backup),
        ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    munit_assert_uint32(linear->state.record.count, ==, 1);
    if(strcmp(family, "cyclic") == 0) {
        DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
        munit_assert_uint32(cyclic->state.record.count, ==, 0);
    }
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_multiple_immediate_writes_survive_abort(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    create_standard_file(fixture.session, 5);
    open_transaction_family(&fixture, "backup");
    const uint8_t first[] = {0x31, 0x32};
    const uint8_t second[] = {0x41, 0x42};
    const uint8_t third[] = {0x51, 0x52, 0x53, 0x54};
    write_data_status(fixture.session, 1, 0, first, sizeof(first), DFC_STATUS_OK);
    write_data_status(fixture.session, 1, 4, second, sizeof(second), DFC_STATUS_OK);
    write_data_status(fixture.session, 5, 2, third, sizeof(third), DFC_STATUS_OK);
    finish_transaction(&fixture, false);
    DfcFile* before = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    DfcFile* after = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_memory_equal(2, dfc_file_data_const(&fixture.credential, before), first);
    munit_assert_memory_equal(2, dfc_file_data_const(&fixture.credential, before) + 4, second);
    munit_assert_memory_equal(4, dfc_file_data_const(&fixture.credential, after) + 2, third);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_failed_immediate_write_does_not_rebase_snapshot(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    const uint8_t rejected[] = {0x81, 0x82, 0x83, 0x84};
    write_data_status(
        fixture.session, 1, 6, rejected, sizeof(rejected), DFC_STATUS_BOUNDARY_ERROR);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, standard),
        ((uint8_t[]){0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}));
    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_immediate_write_retry_executes_once(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    const uint8_t command[] = {
        0x90, DFC_CMD_WRITE_DATA, 0, 0, 11, 1, 0, 0, 0, 4, 0, 0, 0x91, 0x92, 0x93, 0x94, 0};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    finish_transaction(&fixture, false);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, standard),
        ((uint8_t[]){0x91, 0x92, 0x93, 0x94}));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_authenticated_mac_immediate_write_survives_abort(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    standard->comm_settings = DFC_COMM_MAC;
    standard->access_rights = 0xE0EE;
    uint8_t session_key[DFC_AES_KEY_LENGTH];
    for(size_t index = 0; index < sizeof(session_key); index++) {
        session_key[index] = (uint8_t)(0x40 + index);
    }
    fixture.session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(fixture.session->emulator->secure_messaging);
    fixture.session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    fixture.session->emulator->auth_key_no = 0;
    munit_assert_true(dfc_emulator_native_authentication_active(fixture.session->emulator));

    uint8_t body[] = {1, 0, 0, 0, 4, 0, 0, 0xC1, 0xC2, 0xC3, 0xC4};
    DfcSecureMessaging* twin = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(twin);
    munit_assert_true(
        dfc_secure_messaging_update_ev1_command(twin, DFC_CMD_WRITE_DATA, body, sizeof(body)));
    uint8_t command[5 + sizeof(body) + DFC_WIRE_MAC_LENGTH + 1] = {
        0x90, DFC_CMD_WRITE_DATA, 0, 0, sizeof(body) + DFC_WIRE_MAC_LENGTH};
    memcpy(command + 5, body, sizeof(body));
    memcpy(command + 5 + sizeof(body), twin->iv, DFC_WIRE_MAC_LENGTH);
    exchange_tail_status(fixture.session, command, sizeof(command), DFC_STATUS_OK);
    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_tail_status(fixture.session, abort, sizeof(abort), DFC_STATUS_OK);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, standard),
        ((uint8_t[]){0xC1, 0xC2, 0xC3, 0xC4}));
    dfc_secure_messaging_free(twin);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_iso_update_binary_publishes_existing_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    open_transaction_family(&fixture, "backup");
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    fixture.session->iso_file_selected = true;
    fixture.session->iso_file_index = (size_t)(standard - fixture.credential.files);
    const uint8_t update[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 4, 0xD1, 0xD2, 0xD3, 0xD4};
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, update, sizeof(update), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, abort, sizeof(abort), DFC_STATUS_NO_CHANGES);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, standard),
        ((uint8_t[]){0xD1, 0xD2, 0xD3, 0xD4}));
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, backup),
        ((uint8_t[]){0xB1, 0xB2, 0xB3, 0xB4}));
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_invalid_snapshot_abort_retires_active_transaction(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    DfcEmulator* emulator = fixture.session->emulator;
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    size_t backup_index = (size_t)(backup - fixture.credential.files);
    emulator->transaction_snapshot_offsets[backup_index] =
        (DfcTransactionSnapshotOffset)emulator->transaction_snapshot_pool_length;

    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, abort, sizeof(abort), DFC_STATUS_OK);
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_null(emulator->transaction_snapshot_pool);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, 0);
    munit_assert_size(emulator->transaction_snapshot_pool_capacity, ==, 0);
    munit_assert_true(fixture.credential.dirty);
    munit_assert_false(backup->transaction_pending);
    munit_assert_memory_equal(
        backup->data_len, dfc_file_data_const(&fixture.credential, backup), ((uint8_t[8]){0}));

    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult
    test_missing_snapshot_pool_fails_closed(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    DfcEmulator* emulator = fixture.session->emulator;
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    size_t backup_index = (size_t)(backup - fixture.credential.files);
    uint8_t* orphaned_pool = emulator->transaction_snapshot_pool;
    size_t orphaned_capacity = emulator->transaction_snapshot_pool_capacity;
    emulator->transaction_snapshot_pool = NULL;

    munit_assert_null(
        dfc_emulator_transaction_snapshot_committed_data(emulator, backup_index, NULL));
    size_t backup_length = backup->data_len;
    backup->data_len = 0;
    munit_assert_null(
        dfc_emulator_transaction_snapshot_committed_data(emulator, backup_index, NULL));
    backup->data_len = backup_length;
    memset(
        emulator->transaction_snapshot_captured,
        0,
        sizeof(emulator->transaction_snapshot_captured));
    munit_assert_false(dfc_emulator_transaction_snapshot_capture_file(emulator, backup_index));

    const uint8_t abort[] = {0x90, DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture.session, abort, sizeof(abort), DFC_STATUS_OK);
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_true(fixture.credential.dirty);
    munit_assert_false(backup->transaction_pending);
    munit_assert_memory_equal(
        backup->data_len, dfc_file_data_const(&fixture.credential, backup), ((uint8_t[8]){0}));

    dfc_secure_wipe(orphaned_pool, orphaned_capacity);
    dfc_platform_free(orphaned_pool);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static char* family_values[] = {"backup", "value", "linear", "cyclic", NULL};
static char* finish_values[] = {"commit", "abort", NULL};
static MunitParameterEnum family_params[] = {
    {"family", family_values},
    {"finish", finish_values},
    {NULL, NULL}};
static char* delete_values[] = {"lower", "pending-backup", NULL};
static MunitParameterEnum delete_params[] = {
    {"delete", delete_values},
    {"finish", finish_values},
    {NULL, NULL}};
static char* transaction_family_values[] = {"backup", "linear", "cyclic", NULL};
static char* position_values[] = {"before", "after", NULL};
static MunitParameterEnum immediate_write_params[] = {
    {"family", transaction_family_values},
    {"position", position_values},
    {NULL, NULL}};

static MunitTest tests[] = {
    {"/create-publish-matrix", test_create_publish_matrix, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/journal-capacity-and-lazy-capture",
     test_journal_capacity_and_lazy_capture,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/journal-full-configured-capacity",
     test_journal_preserves_full_configured_capacity,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/journal-max-record-count",
     test_journal_preserves_max_record_count,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/create-family", test_creation_family, NULL, NULL, MUNIT_TEST_OPTION_NONE, family_params},
    {"/delete-rebase",
     test_delete_rebases_pending_files,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     delete_params},
    {"/mixed-cross-app", test_mixed_and_cross_app_offsets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/delete-recreate-same-number",
     test_delete_and_recreate_same_number,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/large-created-backup-zero-read",
     test_large_created_backup_read_streams_zeroes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/retry-once", test_retry_executes_once, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/allocation-failure",
     test_journal_allocation_failure_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/wipe",
     test_journal_is_not_reallocated_and_is_fully_wiped,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/immediate-write-survives-abort",
     test_immediate_write_survives_abort,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     immediate_write_params},
    {"/multiple-immediate-writes",
     test_multiple_immediate_writes_survive_abort,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/failed-immediate-write",
     test_failed_immediate_write_does_not_rebase_snapshot,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/immediate-write-retry",
     test_immediate_write_retry_executes_once,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authenticated-mac-immediate-write",
     test_authenticated_mac_immediate_write_survives_abort,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-update-binary-publishes",
     test_iso_update_binary_publishes_existing_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/invalid-snapshot-abort-retires",
     test_invalid_snapshot_abort_retires_active_transaction,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/missing-snapshot-pool-fails-closed",
     test_missing_snapshot_pool_fails_closed,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_transaction_snapshot", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
