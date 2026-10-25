#include "munit/munit.h"
#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
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
        file->record_size = 3;
        file->max_records = 1;
        file->record_count = 1;
    }

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
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
        ((uint8_t[]){DFC_ISO7816_SW_CONDITIONS_NOT_SATISFIED_HI,
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
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0, 3};
    const uint8_t* commands[] = {read_binary, update_binary, read_record};
    const size_t command_lengths[] = {
        sizeof(read_binary), sizeof(update_binary), sizeof(read_record)};
    const uint8_t file_types[] = {
        DFC_FILE_TYPE_STANDARD_DATA, DFC_FILE_TYPE_STANDARD_DATA, DFC_FILE_TYPE_LINEAR_RECORD};

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

static MunitResult
    test_ev1_read_binary_reports_short_eof(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t reads[][5] = {
        {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 8},
        {0, DFC_ISO7816_INS_READ_BINARY, 0, 2, 4},
        {0, DFC_ISO7816_INS_READ_BINARY, 0, 3, 1},
        {0, DFC_ISO7816_INS_READ_BINARY, 0, 2, 1},
        {0, DFC_ISO7816_INS_READ_BINARY, 0, 2, 0},
    };
    const size_t returned[] = {3, 1, 0, 1, 1};
    const bool short_eof[] = {true, true, true, false, false};

    for(uint8_t generation = DfcGenerationEv1; generation <= DfcGenerationEv3; generation++) {
        for(size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
            DfcCredential credential;
            DfcVirtualPiccSession* session =
                prepare_session(&credential, DFC_FILE_TYPE_STANDARD_DATA);
            credential.card.generation = generation;
            credential.files[0].access_rights = ACCESS_FREE;
            uint8_t response[8];
            size_t response_len;
            exchange(
                session, reads[i], sizeof(reads[i]), response, sizeof(response), &response_len);
            munit_assert_size(response_len, ==, returned[i] + 2);
            bool reports_short_eof = generation == DfcGenerationEv1 && short_eof[i];
            const uint8_t* expected_status =
                reports_short_eof ? ((uint8_t[]){DFC_ISO7816_SW_EOF_BEFORE_LE_HI,
                                                 DFC_ISO7816_SW_EOF_BEFORE_LE_LO}) :
                                    ((uint8_t[]){DFC_ISO7816_SW_OK_HI, DFC_ISO7816_SW_OK_LO});
            munit_assert_memory_equal(2, response + returned[i], expected_status);
            dfc_virtual_picc_session_free(session);
        }
    }
    return MUNIT_OK;
}

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
    uint8_t read[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0, 3};
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
    uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0, 3};
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
            0,
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
    file->sdm_enabled = true;
    file->sdm_read_counter = 41;
    session->emulator->sdm_read_cache_valid = false;
    uint8_t cache[DFC_SDM_READ_CACHE_SIZE];
    memcpy(cache, session->emulator->sdm_read_cache, sizeof(cache));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read, sizeof(read), response, sizeof(response) - 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint32(file->sdm_read_counter, ==, 41);
    munit_assert_false(session->emulator->sdm_read_cache_valid);
    munit_assert_memory_equal(sizeof(cache), session->emulator->sdm_read_cache, cache);
    exchange(session, read, sizeof(read), response, sizeof(response), &response_len);
    munit_assert_uint32(file->sdm_read_counter, ==, 42);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_rejects_standard_iso_file_commands(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 11};
    const uint8_t update[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0, 11};
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
    {"/ev1-read-binary-short-eof",
     test_ev1_read_binary_reports_short_eof,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
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
