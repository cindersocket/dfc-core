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
        file->record_size = 4;
        file->max_records = 3;
        file->record_count = 1;
    }
    if(type == DFC_FILE_TYPE_VALUE) {
        file->value_lower_limit = 0;
        file->value_upper_limit = 100;
        file->value = 10;
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
    memset(fixture->session->emulator->transaction_input, 0xD4, 17);
    fixture->session->emulator->transaction_input_len = 17;
#endif
}

static void finish_transaction(SnapshotFixture* fixture, bool commit) {
    const uint8_t command[] = {
        0x90, commit ? DFC_CMD_COMMIT_TRANSACTION : DFC_CMD_ABORT_TRANSACTION, 0, 0, 0};
    exchange_status(fixture->session, command, sizeof(command), DFC_STATUS_OK);
}

static void
    create_family(DfcVirtualPiccSession* session, const char* family, uint8_t file_number);

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

static void
    create_family(DfcVirtualPiccSession* session, const char* family, uint8_t file_number) {
    DfcCommand command;
    if(strcmp(family, "backup") == 0) {
        DfcCommandDataFile file = {
            .file_no = file_number,
            .comm_settings = DFC_COMM_PLAIN,
            .access_rights = 0xEEEE,
            .size = 4,
        };
        munit_assert_int(dfc_command_create_backup_data_file(&command, &file), ==, DfcCommandOk);
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
    uint8_t apdu[DFC_COMMAND_MAX_DATA + 8];
    size_t apdu_len = 0;
    munit_assert_int(
        dfc_command_to_apdu(&command, apdu, sizeof(apdu), &apdu_len), ==, DfcCommandOk);
    exchange_status(session, apdu, apdu_len, DFC_STATUS_OK);
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
    finish_transaction(&fixture, commit);

    DfcFile* file = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
    munit_assert_not_null(file);
    if(strcmp(family, "backup") == 0) {
        munit_assert_memory_equal(
            4,
            dfc_file_data_const(&fixture.credential, file),
            commit ? ((uint8_t[]){0xC1, 0xC2, 0xC3, 0xC4}) : ((uint8_t[]){0, 0, 0, 0}));
    } else if(strcmp(family, "value") == 0) {
        munit_assert_int32(file->value, ==, commit ? 15 : 10);
        munit_assert_false(file->value_pending);
    } else if(strcmp(family, "linear") == 0 || strcmp(family, "cyclic") == 0) {
        munit_assert_uint32(file->record_count, ==, commit ? 1 : 0);
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
    munit_assert_true(value->value_pending);
    finish_transaction(&fixture, commit);
    if(delete_lower) {
        munit_assert_memory_equal(
            4,
            dfc_file_data_const(&fixture.credential, backup),
            commit ? ((uint8_t[]){0xB1, 0xB1, 0xB1, 0xB1}) :
                     ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    } else {
        munit_assert_null(backup);
    }
    munit_assert_uint32(record->record_count, ==, commit ? 2 : 1);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, record),
        commit ? ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0xA1, 0xA2, 0xA3, 0xA4}) :
                 ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}));
    munit_assert_int32(value->value, ==, commit ? 15 : 10);
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
    munit_assert_uint32(record->record_count, ==, 0);
    fixture_close(&fixture);
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

static MunitResult test_growth_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    dfc_host_fail_allocation_after(DfcAllocEmulator, 1);
    const uint8_t create[] = {
        0x90, DFC_CMD_CREATE_BACKUP_DATA_FILE, 0, 0, 7, 5, 0, 0xEE, 0xEE, 4, 0, 0, 0};
    exchange_status(fixture.session, create, sizeof(create), DFC_STATUS_OUT_OF_EEPROM);
    munit_assert_null(dfc_credential_find_file_in_app(&fixture.credential, 0, 5));
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
    munit_assert_uint32(record->record_count, ==, 1);
    munit_assert_memory_equal(
        12,
        dfc_file_data_const(&fixture.credential, record),
        ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}));
    munit_assert_false(value->value_pending);
    munit_assert_int32(value->value, ==, 10);
    munit_assert_false(fixture.credential.dirty);
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_size(fixture.session->emulator->transaction_input_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(fixture.session->emulator->transaction_input),
        fixture.session->emulator->transaction_input,
        ((uint8_t[sizeof(fixture.session->emulator->transaction_input)]){0}));
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

static MunitResult test_replacement_and_shrink_wipe(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    DfcEmulator* emulator = fixture.session->emulator;
    WipeAudit audit = {
        .target = emulator->transaction_snapshot_pool,
        .length = emulator->transaction_snapshot_pool_length,
    };
    dfc_host_set_free_observer(observe_wipe, &audit);
    create_family(fixture.session, "backup", 5);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.observed);
    munit_assert_true(audit.zeroed);
    size_t old_length = emulator->transaction_snapshot_pool_length;
    const uint8_t remove[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, 5, 0};
    exchange_status(fixture.session, remove, sizeof(remove), DFC_STATUS_OK);
    munit_assert_size(emulator->transaction_snapshot_pool_length, ==, old_length - 4);
    for(size_t index = emulator->transaction_snapshot_pool_length; index < old_length; index++) {
        munit_assert_uint8(emulator->transaction_snapshot_pool[index], ==, 0);
    }
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_immediate_write_survives_abort(
    const MunitParameter params[],
    void* data) {
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

    DfcFile* standard =
        dfc_credential_find_file_in_app(&fixture.credential, 0, file_number);
    munit_assert_memory_equal(
        sizeof(replacement),
        dfc_file_data_const(&fixture.credential, standard) + 2,
        replacement);
    munit_assert_true(fixture.credential.dirty);
    DfcFile* backup = dfc_credential_find_file_in_app(&fixture.credential, 0, 2);
    munit_assert_memory_equal(
        4,
        dfc_file_data_const(&fixture.credential, backup),
        ((uint8_t[]){0x22, 0x22, 0x22, 0x22}));
    DfcFile* linear = dfc_credential_find_file_in_app(&fixture.credential, 0, 3);
    munit_assert_uint32(linear->record_count, ==, 1);
    if(strcmp(family, "cyclic") == 0) {
        DfcFile* cyclic = dfc_credential_find_file_in_app(&fixture.credential, 0, 5);
        munit_assert_uint32(cyclic->record_count, ==, 0);
    }
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_multiple_immediate_writes_survive_abort(
    const MunitParameter params[],
    void* data) {
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
    munit_assert_memory_equal(
        2, dfc_file_data_const(&fixture.credential, before) + 4, second);
    munit_assert_memory_equal(
        4, dfc_file_data_const(&fixture.credential, after) + 2, third);
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
    write_data_status(fixture.session, 1, 6, rejected, sizeof(rejected), DFC_STATUS_BOUNDARY_ERROR);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_memory_equal(
        8,
        dfc_file_data_const(&fixture.credential, standard),
        ((uint8_t[]){0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}));
    munit_assert_false(fixture.session->emulator->transaction_snapshot_active);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_immediate_write_retry_executes_once(
    const MunitParameter params[],
    void* data) {
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

static MunitResult test_immediate_write_preserves_co_pending_value(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    begin_transaction(&fixture);
    const uint8_t replacement[] = {0xA1, 0xA2, 0xA3, 0xA4};
    write_data_status(fixture.session, 1, 0, replacement, sizeof(replacement), DFC_STATUS_OK);
    finish_transaction(&fixture, false);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    DfcFile* value = dfc_credential_find_file_in_app(&fixture.credential, 0, 4);
    munit_assert_memory_equal(
        sizeof(replacement), dfc_file_data_const(&fixture.credential, standard), replacement);
    munit_assert_int32(value->value, ==, 10);
    munit_assert_false(value->value_pending);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_chained_immediate_write_survives_abort(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    SnapshotFixture fixture;
    fixture_open(&fixture);
    DfcFile* standard = dfc_credential_find_file_in_app(&fixture.credential, 0, 1);
    munit_assert_true(dfc_file_resize(&fixture.credential, standard, 100));
    memset(dfc_file_data(&fixture.credential, standard), 0x10, 100);
    open_transaction_family(&fixture, "backup");

    uint8_t expected[100];
    for(size_t index = 0; index < sizeof(expected); index++) {
        expected[index] = (uint8_t)(index + 1);
    }
    uint8_t first[6 + DFC_EV1_MAX_FRAME_PAYLOAD] = {
        0x90, DFC_CMD_WRITE_DATA, 0, 0, DFC_EV1_MAX_FRAME_PAYLOAD, 1, 0, 0, 0, 100, 0, 0};
    memcpy(first + 12, expected, 52);
    exchange_status(fixture.session, first, sizeof(first), DFC_CMD_ADDITIONAL_FRAME);
    uint8_t last[6 + 48] = {0x90, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 48};
    memcpy(last + 5, expected + 52, 48);
    exchange_status(fixture.session, last, sizeof(last), DFC_STATUS_OK);
    finish_transaction(&fixture, false);
    munit_assert_memory_equal(
        sizeof(expected), dfc_file_data_const(&fixture.credential, standard), expected);
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
    uint8_t session_key[DFC_AES_KEY_LENGTH];
    for(size_t index = 0; index < sizeof(session_key); index++) {
        session_key[index] = (uint8_t)(0x40 + index);
    }
    fixture.session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(fixture.session->emulator->secure_messaging);
    fixture.session->emulator->auth_key_no = 0;

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

static char* family_values[] = {
    "backup",
    "value",
    "linear",
    "cyclic",
    NULL};
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
    {"/create-family", test_creation_family, NULL, NULL, MUNIT_TEST_OPTION_NONE, family_params},
    {"/delete-rebase",
     test_delete_rebases_pending_files,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     delete_params},
    {"/mixed-cross-app", test_mixed_and_cross_app_offsets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/retry-once", test_retry_executes_once, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/growth-failure", test_growth_failure_is_atomic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/wipe", test_replacement_and_shrink_wipe, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
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
    {"/immediate-write-with-value",
     test_immediate_write_preserves_co_pending_value,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/chained-immediate-write",
     test_chained_immediate_write_survives_abort,
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
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_transaction_snapshot", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
