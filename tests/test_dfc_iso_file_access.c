#include "munit/munit.h"
#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
#include "dfc_emulator_commands_i.h"
#include "dfc_crypto_internal.h"
#include "des_cmac.h"

static const uint8_t SessionKey[16] = {
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
    0xEF,
};

#define ACCESS_KEY1_READ_KEY2_WRITE 0x12FE
#define ACCESS_FREE                 0xEEEE
#define ACCESS_FREE_READ_ONLY       0xEEFE

static DfcVirtualPiccSession* prepare_session(DfcCredential* credential, uint8_t file_type) {
    load_standard_credential(credential);
    DfcFile* file = &credential->files[0];
    file->type = file_type;
    file->has_iso_file_id = true;
    file->iso_file_id = 0x1001;
    file->access_rights = ACCESS_KEY1_READ_KEY2_WRITE;
    file->comm_settings = DFC_COMM_PLAIN;
    if(file_type == DFC_FILE_TYPE_LINEAR_RECORD) {
        file->state.record.size = 3;
        file->state.record.max_records = 1;
        file->state.record.count = 1;
    }

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    // Start inside the file's application with that file current. The current
    // file is only honoured in the application that holds it, so both are set.
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;
    session->iso_file_selected = true;
    session->iso_file_index = 0;
    return session;
}

static void authenticate_as(DfcVirtualPiccSession* session, uint8_t key_no) {
    munit_assert_null(session->emulator->secure_messaging);
    session->emulator->secure_messaging =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_ISO, SessionKey, sizeof(SessionKey), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_ISO;
    session->emulator->auth_key_no = key_no;
}

static void authenticate_d40_as(DfcVirtualPiccSession* session, uint8_t key_no) {
    munit_assert_null(session->emulator->secure_messaging);
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_LEGACY, SessionKey, sizeof(SessionKey), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_LEGACY;
    session->emulator->auth_key_no = key_no;
}

static void authenticate_ev2_as(DfcVirtualPiccSession* session, uint8_t key_no) {
    session->emulator->ev2_session_active = true;
    session->emulator->ev2_authenticated_key_no = key_no;
}

static void exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    *response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_security_status(const uint8_t* response, size_t response_len) {
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x69, 0x82}));
}

static void assert_conditions_not_satisfied(const uint8_t* response, size_t response_len) {
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        2,
        response,
        ((uint8_t[]){
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_HI,
            DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_LO}));
}

#if DFC_ENABLE_TRANSACTION_MAC
static void add_transaction_mac_file(DfcCredential* credential, size_t app_index) {
    DfcFile* file = dfc_credential_create_file(credential, app_index, 0x0E);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_TRANSACTION_MAC;
}

static MunitResult
    test_transaction_mac_blocks_standard_iso_commands(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    const uint8_t update_binary[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 3};
    const uint8_t append_record[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 1, 0xA5};
    const uint8_t* commands[] = {read_binary, update_binary, read_record, append_record};
    const size_t command_lengths[] = {
        sizeof(read_binary), sizeof(update_binary), sizeof(read_record), sizeof(append_record)};
    const uint8_t file_types[] = {
        DFC_FILE_TYPE_STANDARD_DATA,
        DFC_FILE_TYPE_STANDARD_DATA,
        DFC_FILE_TYPE_LINEAR_RECORD,
        DFC_FILE_TYPE_LINEAR_RECORD};

    for(size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = prepare_session(&credential, file_types[i]);
        DfcFile* target = &credential.files[0];
        target->access_rights = ACCESS_FREE;
        uint8_t before = dfc_file_data(&credential, target)[0];
        add_transaction_mac_file(&credential, target->app_index);
        uint8_t response[8];
        size_t response_len;

        exchange(
            session, commands[i], command_lengths[i], response, sizeof(response), &response_len);
        assert_conditions_not_satisfied(response, response_len);
        munit_assert_uint8(dfc_file_data(&credential, target)[0], ==, before);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult
    test_transaction_mac_blocks_standard_iso_selection(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    DfcFile* target = &credential.files[0];
    add_transaction_mac_file(&credential, target->app_index);
    const DfcApplication* app = &credential.apps[target->app_index];
    DfcEmulatorSelectedApplication selection_before = session->emulator->selected_application;
    size_t selected_app_before = session->emulator->selected_app_index;
    bool file_selected_before = session->iso_file_selected;
    size_t selected_file_before = session->iso_file_index;
    uint8_t select_app[5 + sizeof(app->iso_aid)] = {
        0, DFC_ISO7816_INS_SELECT, DFC_ISO7816_SELECT_BY_DF_NAME, 0, app->iso_aid_len};
    memcpy(select_app + 5, app->iso_aid, app->iso_aid_len);
    uint8_t response[8];
    size_t response_len;

    exchange(session, select_app, 5 + app->iso_aid_len, response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);
    munit_assert_int(session->emulator->selected_application, ==, selection_before);
    munit_assert_size(session->emulator->selected_app_index, ==, selected_app_before);
    munit_assert_true(session->iso_file_selected == file_selected_before);
    munit_assert_size(session->iso_file_index, ==, selected_file_before);

    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = target->app_index;
    const uint8_t select_file[] = {
        0,
        DFC_ISO7816_INS_SELECT,
        DFC_ISO7816_SELECT_CHILD_EF,
        0,
        2,
        (uint8_t)(target->iso_file_id >> 8),
        (uint8_t)target->iso_file_id};
    exchange(session, select_file, sizeof(select_file), response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);
    munit_assert_int(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);
    munit_assert_size(session->emulator->selected_app_index, ==, target->app_index);
    munit_assert_true(session->iso_file_selected == file_selected_before);
    munit_assert_size(session->iso_file_index, ==, selected_file_before);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}
#endif

static MunitResult test_iso_binary_access_family(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    uint8_t response[32];
    size_t response_len;

    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    uint8_t* data = dfc_file_data(&credential, &credential.files[0]);
    uint8_t original[3];
    memcpy(original, data, sizeof(original));

    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    munit_assert_memory_equal(sizeof(original), data, original);

    authenticate_as(session, 0);
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    munit_assert_memory_equal(sizeof(original), data, original);
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    data = dfc_file_data(&credential, &credential.files[0]);
    authenticate_as(session, 1);
    read[4] = 11;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 13);
    munit_assert_memory_equal(3, response, data);
    munit_assert_memory_equal(2, response + 11, ((uint8_t[]){0x90, 0x00}));
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    munit_assert_uint8(data[0], ==, original[0]);
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    data = dfc_file_data(&credential, &credential.files[0]);
    authenticate_as(session, 2);
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint8(data[0], ==, 0xA5);
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.files[0].access_rights = ACCESS_FREE;
    data = dfc_file_data(&credential, &credential.files[0]);
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint8(data[0], ==, 0xA5);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_record_access_family(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t read[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 3};
    uint8_t response[32];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    uint8_t* data = dfc_file_data(&credential, &credential.files[0]);

    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    authenticate_as(session, 0);
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    data = dfc_file_data(&credential, &credential.files[0]);
    authenticate_as(session, 1);
    read[4] = 11;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 13);
    munit_assert_memory_equal(3, response, data);
    munit_assert_memory_equal(2, response + 11, ((uint8_t[]){0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_append_record(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[8];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    file->state.record.size = 3;
    file->state.record.max_records = 3;
    file->state.record.count = 0;
    munit_assert_true(dfc_file_resize(&credential, file, 9));
    memset(dfc_file_data(&credential, file), 0xCC, 9);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;

    const uint8_t append_current[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 2, 0xA1, 0xA2};
    session->emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
    exchange(
        session, append_current, sizeof(append_current), response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);
    munit_assert_uint32(file->state.record.count, ==, 0);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;

    response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, append_current, sizeof(append_current), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint32(file->state.record.count, ==, 0);

    exchange(
        session, append_current, sizeof(append_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint32(file->state.record.count, ==, 1);
    munit_assert_memory_equal(
        3, dfc_file_data(&credential, file), ((uint8_t[]){0xA1, 0xA2, 0x00}));
    munit_assert_false(file->transaction_pending);

    session->iso_file_selected = false;
    uint8_t append_sfi[] = {
        0,
        DFC_ISO7816_INS_APPEND_RECORD,
        0,
        (uint8_t)((file->iso_file_id & 0x1F) << 3),
        3,
        0xB1,
        0xB2,
        0xB3};
    exchange(session, append_sfi, sizeof(append_sfi), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_true(session->iso_file_selected);
    munit_assert_uint32(file->state.record.count, ==, 2);
    munit_assert_memory_equal(
        3, dfc_file_data(&credential, file) + 3, ((uint8_t[]){0xB1, 0xB2, 0xB3}));

    const uint8_t malformed[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 2, 0x01};
    exchange(session, malformed, sizeof(malformed), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x67, 0x00}));
    const uint8_t bad_p2[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 1, 1, 0x01};
    exchange(session, bad_p2, sizeof(bad_p2), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x6A, 0x86}));

    const uint8_t append_full[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 3, 1, 2, 3};
    exchange(session, append_full, sizeof(append_full), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    exchange(session, append_full, sizeof(append_full), response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);

    authenticate_ev2_as(session, 0);
    exchange(session, append_full, sizeof(append_full), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_append_record_sfi_selects_file(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[8];
    size_t response_len = 0;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    DfcFile* target = &credential.files[0];
    target->access_rights = ACCESS_FREE;
    target->state.record.size = 3;
    target->state.record.max_records = 4;
    target->state.record.count = 0;
    munit_assert_true(dfc_file_resize(&credential, target, 12));
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = target->app_index;

    DfcFile* other = dfc_credential_create_file(&credential, target->app_index, 0x0E);
    munit_assert_not_null(other);
    other->type = DFC_FILE_TYPE_STANDARD_DATA;
    other->has_iso_file_id = true;
    other->iso_file_id = 0x1002;
    other->access_rights = ACCESS_FREE;
    other->comm_settings = DFC_COMM_PLAIN;
    munit_assert_true(dfc_file_resize(&credential, other, 8));
    session->iso_file_selected = true;
    session->iso_file_index = (size_t)(other - credential.files);

    // A short ISO file identifier selects its file for this
    // and later operations, and APPEND RECORD reads it exactly like READ
    // RECORD. A later append that names no file therefore lands in the target.
    // Measured: hardware_physical_ev3_2k_iso_file_negatives.vec.
    const uint8_t append_sfi[] = {
        0,
        DFC_ISO7816_INS_APPEND_RECORD,
        0,
        (uint8_t)((target->iso_file_id & 0x1F) << 3),
        3,
        0x11,
        0x22,
        0x33,
    };
    exchange(session, append_sfi, sizeof(append_sfi), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_true(session->iso_file_selected);
    munit_assert_size(session->iso_file_index, ==, (size_t)(target - credential.files));

    const uint8_t append_current[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 3, 0x44, 0x55, 0x66};
    exchange(
        session, append_current, sizeof(append_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint32(target->state.record.count, ==, 2);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_cyclic_single_slot_rejected_consistently(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[8];
    size_t response_len = 0;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_CYCLIC_RECORD);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    file->state.record.size = 3;
    file->state.record.max_records = 1;
    file->state.record.count = 0;
    munit_assert_true(dfc_file_resize(&credential, file, 3));
    memset(dfc_file_data(&credential, file), 0xCC, 3);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;

    uint8_t native_write[] = {DFC_CMD_WRITE_RECORD, file->number, 0, 0, 0, 3, 0, 0, 1, 2, 3};
    exchange(
        session, native_write, sizeof(native_write), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_BOUNDARY_ERROR);
    native_write[0] = DFC_CMD_WRITE_RECORD_ISO;
    exchange(
        session, native_write, sizeof(native_write), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_BOUNDARY_ERROR);

    const uint8_t append[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 3, 1, 2, 3};
    exchange(session, append, sizeof(append), response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);
    munit_assert_uint32(file->state.record.count, ==, 0);
    munit_assert_false(file->transaction_pending);
    munit_assert_memory_equal(
        3, dfc_file_data(&credential, file), ((uint8_t[]){0xCC, 0xCC, 0xCC}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_append_record_transaction_and_cyclic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[8];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    file->state.record.size = 3;
    file->state.record.max_records = 3;
    file->state.record.count = 0;
    munit_assert_true(dfc_file_resize(&credential, file, 9));
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;

    // How an ISO append interacts with a native write still waiting for
    // CommitTransaction is measured on a genuine card and replayed from
    // hardware_physical_ev3_2k_iso_write_transaction.vec, not asserted here.
    const uint8_t append_extended[] = {
        0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 0, 0, 3, 0x21, 0x22, 0x23};
    exchange(
        session,
        append_extended,
        sizeof(append_extended),
        response,
        sizeof(response),
        &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint32(file->state.record.count, ==, 1);
    munit_assert_memory_equal(
        3, dfc_file_data(&credential, file), ((uint8_t[]){0x21, 0x22, 0x23}));

    file->type = DFC_FILE_TYPE_CYCLIC_RECORD;
    file->state.record.count = 2;
    memcpy(dfc_file_data(&credential, file), ((uint8_t[]){1, 1, 1, 2, 2, 2}), 6);
    const uint8_t append_cyclic[] = {0, DFC_ISO7816_INS_APPEND_RECORD, 0, 0, 3, 3, 3, 3};
    exchange(
        session, append_cyclic, sizeof(append_cyclic), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint32(file->state.record.count, ==, 2);
    munit_assert_memory_equal(
        6, dfc_file_data(&credential, file), ((uint8_t[]){2, 2, 2, 3, 3, 3}));

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    dfc_emulator_command_transaction_set_record_operation(
        session->emulator, file, RecordTransactionUpdate, 0);
    exchange(
        session, append_cyclic, sizeof(append_cyclic), response, sizeof(response), &response_len);
    assert_conditions_not_satisfied(response, response_len);
#endif
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// No capture exists for cyclic ISO numbering (the captured card had no memory
// left to build a cyclic file), so this states the assumed rule: record 1 is the
// most recently written, record 0 is the last written, and a read-through (P2
// bits 2-0 = 101b) runs to the oldest. The linear half of the same rules is
// measured in hardware_physical_ev3_2k_iso_file_negatives.vec.
static MunitResult
    test_iso_read_record_cyclic_numbering(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_CYCLIC_RECORD);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    file->state.record.size = 3;
    file->state.record.max_records = 4;
    file->state.record.count = 3;
    munit_assert_true(dfc_file_resize(&credential, file, 12));
    // Stored oldest first: 1, 2, 3.
    memcpy(
        dfc_file_data(&credential, file), ((uint8_t[]){1, 1, 1, 2, 2, 2, 3, 3, 3, 0, 0, 0}), 12);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = file->app_index;
    session->iso_file_selected = true;
    session->iso_file_index = 0;

    static const struct {
        uint8_t p1, p2, le;
        size_t length;
        uint8_t body[9];
    } reads[] = {
        {1, 0x04, 0, 3, {3, 3, 3}},
        {3, 0x04, 0, 3, {1, 1, 1}},
        {0, 0x04, 0, 3, {3, 3, 3}},
        {1, 0x05, 0, 9, {3, 3, 3, 2, 2, 2, 1, 1, 1}},
        {2, 0x05, 0, 6, {2, 2, 2, 1, 1, 1}},
        {1, 0x05, 4, 4, {3, 3, 3, 2}},
    };
    for(size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
        const uint8_t command[] = {
            0, DFC_ISO7816_INS_READ_RECORD, reads[i].p1, reads[i].p2, reads[i].le};
        exchange(session, command, sizeof(command), response, sizeof(response), &response_len);
        munit_assert_size(response_len, ==, reads[i].length + 2);
        munit_assert_memory_equal(reads[i].length, response, reads[i].body);
        munit_assert_memory_equal(2, response + reads[i].length, ((uint8_t[]){0x90, 0x00}));
    }
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A file made current in one application must never be reachable from another.
// Before this was enforced, selecting a second application (and authenticating
// there) let READ BINARY with no file named return the first application's
// file, protected by the wrong application's keys. The current file now
// belongs to the application that was selected when it was chosen, ends when
// the selection changes (even if the same application is selected again), and
// ends on a new ISO 14443-3 selection even when the host never sent RATS.
static MunitResult
    test_current_file_does_not_cross_applications(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.files[0].access_rights = ACCESS_FREE;
    const DfcApplication first_app = credential.apps[credential.files[0].app_index];
    const uint8_t second_aid[3] = {0x0A, 0x0B, 0x0C};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &credential, second_aid, 0x0F, DFC_KEY_TYPE_AES | 1));
    // Native SelectApplication takes the identifier least significant byte first.
    const uint8_t select_first[] = {
        0x90,
        DFC_CMD_SELECT_APPLICATION,
        0,
        0,
        3,
        first_app.aid[2],
        first_app.aid[1],
        first_app.aid[0],
        0};
    const uint8_t select_second[] = {
        0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, second_aid[2], second_aid[1], second_aid[0], 0};
    const uint8_t select_file[] = {0, DFC_ISO7816_INS_SELECT, 0x02, 0x0C, 2, 0x10, 0x01};
    const uint8_t read_current[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    const uint8_t refused[] = {0x69, 0x85};

    // Inside the file's own application the current file reads normally.
    exchange(
        session, select_first, sizeof(select_first), response, sizeof(response), &response_len);
    exchange(session, select_file, sizeof(select_file), response, sizeof(response), &response_len);
    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 5);
    munit_assert_memory_equal(2, response + 3, ((uint8_t[]){0x90, 0x00}));

    // Another application, and then the first one again: no current file.
    exchange(
        session, select_second, sizeof(select_second), response, sizeof(response), &response_len);
    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, refused);
    exchange(
        session, select_first, sizeof(select_first), response, sizeof(response), &response_len);
    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, refused);

    // A new selection of the card ends it as well, with no RATS in between.
    exchange(session, select_file, sizeof(select_file), response, sizeof(response), &response_len);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, refused);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// The current file is remembered as a position in the credential's file array,
// and deleting a file shifts every later file down one place. Without care the
// position would then name the NEXT file, which the reader never selected. The
// current file must instead end whenever the set of files changes.
static MunitResult
    test_current_file_ends_when_a_file_is_deleted(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    DfcFile* first = &credential.files[0];
    first->access_rights = ACCESS_FREE;
    // A second file right after it, with its own ISO id and free access.
    DfcFile* second = dfc_credential_create_file(&credential, first->app_index, 0x01);
    munit_assert_not_null(second);
    second->type = DFC_FILE_TYPE_STANDARD_DATA;
    second->has_iso_file_id = true;
    second->iso_file_id = 0x1002;
    second->access_rights = ACCESS_FREE;
    second->comm_settings = DFC_COMM_PLAIN;
    munit_assert_true(dfc_file_resize(&credential, second, 4));
    // And a third, which the stale position would land on after the delete. It
    // is readable, so a wrong answer here would be a successful read of a file
    // the reader never selected.
    DfcFile* third = dfc_credential_create_file(&credential, credential.files[0].app_index, 0x02);
    munit_assert_not_null(third);
    third->type = DFC_FILE_TYPE_STANDARD_DATA;
    third->has_iso_file_id = true;
    third->iso_file_id = 0x1003;
    third->access_rights = ACCESS_FREE;
    third->comm_settings = DFC_COMM_PLAIN;
    munit_assert_true(dfc_file_resize(&credential, third, 4));
    first = &credential.files[0];

    const uint8_t select_second[] = {0, DFC_ISO7816_INS_SELECT, 0x02, 0x0C, 2, 0x10, 0x02};
    const uint8_t read_current[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 2};
    exchange(
        session, select_second, sizeof(select_second), response, sizeof(response), &response_len);
    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response + response_len - 2, ((uint8_t[]){0x90, 0x00}));

    // Delete the first file. The second slides into its place in the array.
    const uint8_t delete_first[] = {0x90, DFC_CMD_DELETE_FILE, 0, 0, 1, first->number, 0};
    exchange(
        session, delete_first, sizeof(delete_first), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x00}));

    exchange(
        session, read_current, sizeof(read_current), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x69, 0x85}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A file's `state` is a union shared by data, record and value files, and the
// secure-dynamic-messaging part of a data file lives in the same bytes as a
// record file's count and maximum and a value file's limits and balance.
// ChangeFileSettings used to clear the SDM part unconditionally, so changing the
// access rights of a record or value file silently wiped what it held. It must
// change the rights and nothing else.
static MunitResult test_change_file_settings_keeps_record_and_value_state(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    DfcFile* records = &credential.files[0];
    records->access_rights = ACCESS_FREE;
    records->state.record.size = 4;
    records->state.record.max_records = 4;
    records->state.record.count = 2;
    munit_assert_true(dfc_file_resize(&credential, records, 16));

    DfcFile* value = dfc_credential_create_file(&credential, records->app_index, 0x03);
    munit_assert_not_null(value);
    records = &credential.files[0];
    value->type = DFC_FILE_TYPE_VALUE;
    value->access_rights = ACCESS_FREE;
    value->comm_settings = DFC_COMM_PLAIN;
    value->state.value.lower_limit = -5;
    value->state.value.upper_limit = 500;
    value->state.value.current = 123;
    value->state.value.limited_credit = 1;
    value->state.value.limited_credit_value = 77;

    // New rights EEEE, plain communication, for each file (ChangeFileSettings).
    const uint8_t change_records[] = {0x90, 0x5F, 0, 0, 4, records->number, 0, 0xEE, 0xEE, 0};
    const uint8_t change_value[] = {0x90, 0x5F, 0, 0, 4, value->number, 0, 0xEE, 0xEE, 0};
    exchange(
        session, change_records, sizeof(change_records), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x00}));
    exchange(
        session, change_value, sizeof(change_value), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x00}));

    munit_assert_uint32(records->state.record.size, ==, 4);
    munit_assert_uint32(records->state.record.max_records, ==, 4);
    munit_assert_uint32(records->state.record.count, ==, 2);
    munit_assert_int32(value->state.value.lower_limit, ==, -5);
    munit_assert_int32(value->state.value.upper_limit, ==, 500);
    munit_assert_int32(value->state.value.current, ==, 123);
    munit_assert_uint8(value->state.value.limited_credit, ==, 1);
    munit_assert_int32(value->state.value.limited_credit_value, ==, 77);

    // The same bytes are what a well-formed secure-dynamic-messaging body would
    // overwrite: UID mirroring on, options 0x81, access EFFF, UID offset 0x123456.
    // Those fields land on the record count and the value balance and limits, so
    // a caller holding only the Change right could forge them (and then read
    // another file's bytes through a forged count). A non-data file refuses an
    // SDM body outright and nothing about it changes.
    const uint8_t sdm_body[] = {0x40, 0xEE, 0xEE, 0x81, 0xFF, 0xEF, 0x56, 0x34, 0x12};
    for(size_t kind = 0; kind < 2; kind++) {
        uint8_t attack[5 + 1 + sizeof(sdm_body) + 1] = {0x90, 0x5F, 0, 0, 1 + sizeof(sdm_body)};
        attack[5] = kind == 0 ? records->number : value->number;
        memcpy(attack + 6, sdm_body, sizeof(sdm_body));
        exchange(session, attack, sizeof(attack), response, sizeof(response), &response_len);
        munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x9E}));
    }
    munit_assert_uint32(records->state.record.max_records, ==, 4);
    munit_assert_uint32(records->state.record.count, ==, 2);
    munit_assert_int32(value->state.value.upper_limit, ==, 500);
    munit_assert_int32(value->state.value.current, ==, 123);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A write that is still waiting for CommitTransaction must not be readable. The
// native read already shows the committed bytes; the ISO read used to show the
// staged ones, so data written under one right could be seen through the other
// path before it was ever committed.
static MunitResult
    test_iso_read_shows_only_committed_backup_data(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_BACKUP_DATA);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    munit_assert_true(dfc_file_resize(&credential, file, 4));
    memset(dfc_file_data(&credential, file), 0x11, 4);

    // Native WriteData of AA BB at offset 0, staged and not yet committed.
    const uint8_t write[] = {
        0x90, DFC_CMD_WRITE_DATA, 0, 0, 9, file->number, 0, 0, 0, 2, 0, 0, 0xAA, 0xBB, 0};
    exchange(session, write, sizeof(write), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x00}));

    const uint8_t iso_read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 4};
    exchange(session, iso_read, sizeof(iso_read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 6);
    munit_assert_memory_equal(6, response, ((uint8_t[]){0x11, 0x11, 0x11, 0x11, 0x90, 0x00}));

    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    exchange(session, commit, sizeof(commit), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, 0x00}));
    exchange(session, iso_read, sizeof(iso_read), response, sizeof(response), &response_len);
    munit_assert_memory_equal(6, response, ((uint8_t[]){0xAA, 0xBB, 0x11, 0x11, 0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// A credential read back only partly can declare more records than it stores
// (the decoder accepts it). Every record command indexes the file's bytes by
// record number times record size, so before this was checked an unauthenticated
// reader could read, or overwrite, whatever followed the file in the file pool:
// another file's contents and, past that, the application keys. Every record
// command, native and ISO, must refuse such a file and touch nothing.
static MunitResult test_record_commands_refuse_a_file_that_stores_fewer_records_than_declared(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_LINEAR_RECORD);
    // UpdateRecord does not exist on EV1.
    credential.card.generation = DfcGenerationEv3;
    DfcFile* records = &credential.files[0];
    records->access_rights = ACCESS_FREE;
    // Declares twelve 16-byte records but stores only one.
    records->state.record.size = 16;
    records->state.record.max_records = 12;
    records->state.record.count = 12;
    munit_assert_true(dfc_file_resize(&credential, records, 16));
    // A file in the same application that only key 0 may touch, right behind it.
    DfcFile* secret = dfc_credential_create_file(&credential, records->app_index, 0x05);
    munit_assert_not_null(secret);
    secret->type = DFC_FILE_TYPE_STANDARD_DATA;
    secret->access_rights = 0x0000;
    secret->comm_settings = DFC_COMM_PLAIN;
    munit_assert_true(dfc_file_resize(&credential, secret, 32));
    memset(dfc_file_data(&credential, secret), 0x5E, 32);
    records = &credential.files[0];
    const uint8_t file_number = records->number;

    // ISO READ RECORD, record 9 of the current file: memory failure, no data.
    const uint8_t iso_read[] = {0, DFC_ISO7816_INS_READ_RECORD, 9, 0x04, 0};
    exchange(session, iso_read, sizeof(iso_read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x65, 0x81}));

    // Native ReadRecords of record 3, then WriteRecord and UpdateRecord at record 3.
    const uint8_t read_records[] = {
        0x90, DFC_CMD_READ_RECORDS, 0, 0, 7, file_number, 3, 0, 0, 1, 0, 0, 0};
    exchange(
        session, read_records, sizeof(read_records), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OUT_OF_EEPROM}));
    const uint8_t write_record[] = {
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
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        0};
    exchange(
        session, write_record, sizeof(write_record), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OUT_OF_EEPROM}));
    const uint8_t update_record[] = {0x90, DFC_CMD_UPDATE_RECORD_ISO,
                                     0,    0,
                                     14,   file_number,
                                     3,    0,
                                     0,    0,
                                     0,    0,
                                     4,    0,
                                     0,    0xDE,
                                     0xAD, 0xBE,
                                     0xEF, 0};
    exchange(
        session, update_record, sizeof(update_record), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, DFC_STATUS_OUT_OF_EEPROM);
    // ClearRecordFile refuses too, and leaves the declared count alone.
    const uint8_t clear_records[] = {0x90, DFC_CMD_CLEAR_RECORD_FILE, 0, 0, 1, file_number, 0};
    exchange(
        session, clear_records, sizeof(clear_records), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[1], ==, DFC_STATUS_OUT_OF_EEPROM);
    munit_assert_uint32(records->state.record.count, ==, 12);

    // Nothing behind the file was read into a response or written to.
    const uint8_t* neighbour = dfc_file_data_const(&credential, secret);
    for(size_t i = 0; i < 32; i++)
        munit_assert_uint8(neighbour[i], ==, 0x5E);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

// ChangeFileSettings reads its comm byte and two rights bytes before it looks at
// the rest of the body. A one- or two-byte body with the SDM bit set got past the
// early length check and read one or two bytes beyond the buffer. The command
// goes in an exact-size heap buffer so AddressSan catches any read past it.
static MunitResult test_change_file_settings_short_bodies_do_not_over_read(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.files[0].access_rights = ACCESS_FREE;
    for(size_t body_len = 0; body_len <= 2; body_len++) {
        size_t command_len = 2 + body_len; // command code, file number, then the body
        uint8_t* command = malloc(command_len);
        munit_assert_not_null(command);
        command[0] = DFC_CMD_CHANGE_FILE_SETTINGS;
        command[1] = credential.files[0].number;
        for(size_t i = 0; i < body_len; i++)
            command[2 + i] = 0x40; // SDM bit set
        DfcByteBuf* tx = session->emulator->tx_buffer;
        dfc_bytebuf_reset(tx);
        (void)dfc_emulator_handle_command(session->emulator, command, command_len, tx, NULL);
        free(command);
        munit_assert_size(dfc_bytebuf_get_size_bytes(tx), ==, 1);
        munit_assert_uint8(dfc_bytebuf_get_data(tx)[0], ==, DFC_STATUS_LENGTH_ERROR);
    }
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void assert_iso_mac_response_status(
    const uint8_t* response,
    size_t response_len,
    uint8_t iv[8],
    uint8_t status_hi,
    uint8_t status_lo) {
    munit_assert_size(response_len, ==, 13);
    DfcCryptoSegment segments[] = {
        {.data = response, .length = 3},
        {.data = &status_lo, .length = 1},
    };
    uint8_t expected[8] = {0};
    uint8_t key[sizeof(SessionKey)];
    memcpy(key, SessionKey, sizeof(key));
    munit_assert_true(des_cmac_segments_with_iv(key, sizeof(key), segments, 2, iv, expected));
    munit_assert_memory_equal(sizeof(expected), response + 3, expected);
    munit_assert_memory_equal(2, response + 11, ((uint8_t[]){status_hi, status_lo}));
    memcpy(iv, expected, sizeof(expected));
}

static void assert_iso_mac_response(const uint8_t* response, size_t response_len, uint8_t iv[8]) {
    assert_iso_mac_response_status(
        response, response_len, iv, DFC_ISO7816_SW_OK_HI, DFC_ISO7816_SW_OK_LO);
}

static void assert_d40_mac_response(const uint8_t* response, size_t response_len) {
    munit_assert_size(response_len, ==, 9);
    uint8_t block[DFC_SM_LEGACY_BLOCK_SIZE] = {0};
    uint8_t encrypted[DFC_SM_LEGACY_BLOCK_SIZE] = {0};
    memcpy(block, response, 3);
    DfcCryptoDesBlock cipher;
    munit_assert_true(dfc_crypto_des_block_init(&cipher, true, SessionKey, sizeof(SessionKey)));
    munit_assert_true(dfc_crypto_des_block_crypt(&cipher, block, encrypted));
    dfc_crypto_des_block_clear(&cipher);
    munit_assert_memory_equal(DFC_SM_LEGACY_MAC_LENGTH, response + 3, encrypted);
    munit_assert_memory_equal(2, response + 7, ((uint8_t[]){0x90, 0x00}));
}

static MunitResult test_iso_d40_mac_oracle(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.card.generation = DfcGenerationEv3;
    credential.files[0].comm_settings = DFC_COMM_MAC;
    authenticate_d40_as(session, 1);
    const uint8_t d40_read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 7};
    exchange(session, d40_read, sizeof(d40_read), response, sizeof(response), &response_len);
    assert_d40_mac_response(response, response_len);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_ev1_mac_chaining(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.card.generation = DfcGenerationEv3;
    credential.files[0].comm_settings = DFC_COMM_PLAIN;
    authenticate_as(session, 1);
    const uint8_t ev1_read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 11};
    uint8_t iv[8] = {0};
    exchange(session, ev1_read, sizeof(ev1_read), response, sizeof(response), &response_len);
    assert_iso_mac_response(response, response_len, iv);
    exchange(session, ev1_read, sizeof(ev1_read), response, sizeof(response), &response_len);
    assert_iso_mac_response(response, response_len, iv);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_file_communication_modes(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 3};
    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    uint8_t response[32];
    size_t response_len;

    const uint8_t communication_modes[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    for(uint8_t auth = 0; auth < 3; auth++) {
        for(size_t mode = 0; mode < sizeof(communication_modes); mode++) {
            uint8_t comm = communication_modes[mode];
            for(uint8_t type = DFC_FILE_TYPE_STANDARD_DATA; type <= DFC_FILE_TYPE_LINEAR_RECORD;
                type += 3) {
                DfcCredential credential;
                DfcVirtualPiccSession* session = prepare_session(&credential, type);
                DfcFile* file = &credential.files[0];
                file->comm_settings = comm;
                if(auth == 0)
                    authenticate_d40_as(session, 1);
                else if(auth == 1)
                    authenticate_as(session, 1);
                else
                    authenticate_ev2_as(session, 1);
                uint8_t* read = type == DFC_FILE_TYPE_STANDARD_DATA ? read_binary : read_record;
                read[4] = auth == 0 ? (comm == DFC_COMM_MAC ? 7 : 3) : 11;
                exchange(session, read, 5, response, sizeof(response), &response_len);
                if(auth == 2 || comm == DFC_COMM_ENCIPHERED) {
                    assert_security_status(response, response_len);
                } else if(auth == 0 && comm == DFC_COMM_PLAIN) {
                    munit_assert_size(response_len, ==, 5);
                    munit_assert_memory_equal(2, response + 3, ((uint8_t[]){0x90, 0x00}));
                } else {
                    size_t mac_len = auth == 0 ? DFC_SM_LEGACY_MAC_LENGTH : DFC_WIRE_MAC_LENGTH;
                    munit_assert_size(response_len, ==, 3 + mac_len + 2);
                    munit_assert_memory_equal(
                        2, response + 3 + mac_len, ((uint8_t[]){0x90, 0x00}));
                }
                dfc_virtual_picc_session_free(session);
            }

            DfcCredential credential;
            DfcVirtualPiccSession* session =
                prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
            DfcFile* file = &credential.files[0];
            uint8_t* data = dfc_file_data(&credential, file);
            uint8_t original = data[0];
            file->comm_settings = comm;
            if(auth == 0)
                authenticate_d40_as(session, 2);
            else if(auth == 1)
                authenticate_as(session, 2);
            else
                authenticate_ev2_as(session, 2);
            exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
            if(auth != 2 && comm == DFC_COMM_PLAIN) {
                munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
                munit_assert_uint8(data[0], ==, 0xA5);
            } else {
                assert_security_status(response, response_len);
                munit_assert_uint8(data[0], ==, original);
            }
            dfc_virtual_picc_session_free(session);
        }
    }

    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE_READ_ONLY;
    file->comm_settings = DFC_COMM_MAC;
    read_binary[4] = 3;
    exchange(session, read_binary, 5, response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 5);
    munit_assert_memory_equal(2, response + 3, ((uint8_t[]){0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_backup_update_commits_immediately(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    uint8_t response[8];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_BACKUP_DATA);
    uint8_t* data = dfc_file_data(&credential, &credential.files[0]);
    uint8_t original = data[0];

    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    munit_assert_uint8(data[0], ==, original);
    authenticate_as(session, 2);
    exchange(session, update, sizeof(update), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x90, 0x00}));
    munit_assert_uint8(data[0], ==, 0xA5);
    munit_assert_false(dfc_emulator_abort_transaction(session->emulator));
    munit_assert_uint8(data[0], ==, 0xA5);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_mac_read_capacity_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 11};
    uint8_t response[13];
    size_t response_len = SIZE_MAX;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.files[0].comm_settings = DFC_COMM_MAC;
    authenticate_as(session, 1);
    DfcSecureMessaging before = *session->emulator->secure_messaging;

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read, sizeof(read), response, sizeof(response) - 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_memory_equal(sizeof(before), session->emulator->secure_messaging, &before);
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    uint8_t iv[8] = {0};
    assert_iso_mac_response(response, response_len, iv);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_mac_le_boundaries(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[16];
    size_t response_len;

    for(uint8_t type = DFC_FILE_TYPE_STANDARD_DATA; type <= DFC_FILE_TYPE_LINEAR_RECORD;
        type += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = prepare_session(&credential, type);
        credential.card.generation = DfcGenerationEv3;
        credential.files[0].comm_settings = DFC_COMM_PLAIN;
        authenticate_as(session, 1);
        uint8_t read[] = {
            0,
            type == DFC_FILE_TYPE_STANDARD_DATA ? DFC_ISO7816_INS_READ_BINARY :
                                                  DFC_ISO7816_INS_READ_RECORD,
            type == DFC_FILE_TYPE_STANDARD_DATA ? 0 : 1,
            type == DFC_FILE_TYPE_STANDARD_DATA ? 0 : 0x04,
            DFC_WIRE_MAC_LENGTH,
        };
        DfcSecureMessaging before = *session->emulator->secure_messaging;
        exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
        munit_assert_memory_equal(2, response, ((uint8_t[]){0x6C, 0x00}));
        munit_assert_memory_equal(sizeof(before), session->emulator->secure_messaging, &before);

        read[4] = DFC_WIRE_MAC_LENGTH + 1;
        exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
        munit_assert_size(response_len, ==, 11);
        munit_assert_memory_equal(2, response + 9, ((uint8_t[]){0x90, 0x00}));
        read[4] = 0xFF;
        exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
        munit_assert_size(response_len, ==, 13);
        munit_assert_memory_equal(2, response + 11, ((uint8_t[]){0x90, 0x00}));
        dfc_virtual_picc_session_free(session);
    }

    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.card.generation = DfcGenerationEv3;
    credential.files[0].comm_settings = DFC_COMM_MAC;
    authenticate_d40_as(session, 1);
    uint8_t read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, DFC_SM_LEGACY_MAC_LENGTH};
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x6C, 0x00}));
    read[4]++;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 7);
    munit_assert_memory_equal(2, response + 5, ((uint8_t[]){0x90, 0x00}));
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.card.generation = DfcGenerationEv1;
    credential.files[0].comm_settings = DFC_COMM_MAC;
    authenticate_d40_as(session, 1);
    read[4] = DFC_SM_LEGACY_MAC_LENGTH;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_d40_mac_response(response, response_len);
    dfc_virtual_picc_session_free(session);

    session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    credential.card.generation = DfcGenerationEv1;
    credential.files[0].comm_settings = DFC_COMM_PLAIN;
    authenticate_as(session, 1);
    read[4] = DFC_WIRE_MAC_LENGTH;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    uint8_t iv[8] = {0};
    assert_iso_mac_response(response, response_len, iv);
    read[4] = 0xFF;
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    assert_iso_mac_response_status(
        response,
        response_len,
        iv,
        DFC_ISO7816_SW_EOF_BEFORE_LE_HI,
        DFC_ISO7816_SW_EOF_BEFORE_LE_LO);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_sdm_capacity_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    uint8_t response[5];
    size_t response_len = SIZE_MAX;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    DfcFile* file = &credential.files[0];
    file->access_rights = ACCESS_FREE;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    file->state.data.sdm_read_counter = 41;
    session->emulator->sdm_read_cache_valid = false;
    session->emulator->sdm_read_cache_family = 0;
    uint8_t cache[DFC_SDM_READ_CACHE_SIZE];
    memcpy(cache, session->emulator->sdm_read_cache, sizeof(cache));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read, sizeof(read), response, sizeof(response) - 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 41);
    munit_assert_false(session->emulator->sdm_read_cache_valid);
    munit_assert_uint8(session->emulator->sdm_read_cache_family, ==, 0);
    munit_assert_memory_equal(sizeof(cache), session->emulator->sdm_read_cache, cache);
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 42);
    munit_assert_uint8(session->emulator->sdm_read_cache_family, ==, DfcSdmReadFamilyIso7816);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_rejects_standard_iso_file_commands(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 11};
    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0x04, 11};
    const uint8_t* commands[] = {read_binary, update, read_record};
    const size_t command_lengths[] = {sizeof(read_binary), sizeof(update), sizeof(read_record)};
    const uint8_t communication_modes[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    uint8_t response[16];
    size_t response_len;

    for(size_t mode = 0; mode < sizeof(communication_modes); mode++) {
        for(size_t command_index = 0; command_index < 3; command_index++) {
            DfcCredential credential;
            uint8_t file_type = command_index == 2 ? DFC_FILE_TYPE_LINEAR_RECORD :
                                                     DFC_FILE_TYPE_STANDARD_DATA;
            DfcVirtualPiccSession* session = prepare_session(&credential, file_type);
            credential.files[0].comm_settings = communication_modes[mode];
            authenticate_ev2_as(session, command_index == 1 ? 2 : 1);
            uint8_t before = dfc_file_data(&credential, &credential.files[0])[0];
            exchange(
                session,
                commands[command_index],
                command_lengths[command_index],
                response,
                sizeof(response),
                &response_len);
            assert_security_status(response, response_len);
            munit_assert_uint8(dfc_file_data(&credential, &credential.files[0])[0], ==, before);
            dfc_virtual_picc_session_free(session);
        }
    }
    return MUNIT_OK;
}

static MunitResult
    test_native_and_iso_reads_share_access_policy(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t native_read[] = {
        DFC_ISO7816_CLA_WRAPPER,
        DFC_CMD_READ_DATA,
        0,
        0,
        7,
        0x0F,
        0,
        0,
        0,
        3,
        0,
        0,
        0,
    };
    const uint8_t iso_read[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    uint8_t response[16];
    size_t response_len;
    DfcCredential credential;
    DfcVirtualPiccSession* session = prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = 0;

    exchange(session, native_read, sizeof(native_read), response, sizeof(response), &response_len);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_AUTHENTICATION_ERR}));
    exchange(session, iso_read, sizeof(iso_read), response, sizeof(response), &response_len);
    assert_security_status(response, response_len);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
#if DFC_ENABLE_TRANSACTION_MAC
    {"/transaction-mac-blocks-commands",
     test_transaction_mac_blocks_standard_iso_commands,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac-blocks-selection",
     test_transaction_mac_blocks_standard_iso_selection,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {"/binary-access-family",
     test_iso_binary_access_family,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/record-access-family",
     test_iso_record_access_family,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/append-record", test_iso_append_record, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/append-record-sfi-selects-file",
     test_iso_append_record_sfi_selects_file,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cyclic-single-slot-rejected-consistently",
     test_cyclic_single_slot_rejected_consistently,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/read-record-cyclic-numbering",
     test_iso_read_record_cyclic_numbering,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/current-file-ends-when-a-file-is-deleted",
     test_current_file_ends_when_a_file_is_deleted,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-keeps-record-and-value-state",
     test_change_file_settings_keeps_record_and_value_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-read-shows-only-committed-backup-data",
     test_iso_read_shows_only_committed_backup_data,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/record-commands-refuse-a-file-that-stores-fewer-records-than-declared",
     test_record_commands_refuse_a_file_that_stores_fewer_records_than_declared,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-short-bodies-do-not-over-read",
     test_change_file_settings_short_bodies_do_not_over_read,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/current-file-does-not-cross-applications",
     test_current_file_does_not_cross_applications,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/append-record-transaction-cyclic",
     test_iso_append_record_transaction_and_cyclic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/communication-modes",
     test_iso_file_communication_modes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/d40-mac-oracle", test_iso_d40_mac_oracle, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev1-mac-chaining", test_iso_ev1_mac_chaining, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/backup-update-commits",
     test_iso_backup_update_commits_immediately,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac-read-capacity-atomic",
     test_iso_mac_read_capacity_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac-le-boundaries", test_iso_mac_le_boundaries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/sdm-capacity-atomic",
     test_iso_sdm_capacity_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-standard-iso-rejected",
     test_ev2_rejects_standard_iso_file_commands,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/native-iso-access-parity",
     test_native_and_iso_reads_share_access_policy,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_iso_file_access", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
