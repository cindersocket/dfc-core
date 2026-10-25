#include "dfc_emulator_i.h"
#include "dfc_ev2.h"
#include "dfc_ev2_crypto.h"
#include "dfc_virtual_picc.h"

#include "munit/munit.h"

#include <string.h>

static DfcVirtualPiccSession*
    open_file(DfcCredential* credential, uint8_t comm, uint16_t access_rights, uint8_t fill) {
    memset(credential, 0, sizeof(*credential));
    credential->card.generation = DfcGenerationEv3;
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}),
        DFC_DESFIRE_UID_LEN);
    const uint8_t aid[] = {1, 2, 3};
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(credential, aid, 0x0F, 0x81));
    DfcFile* file = dfc_credential_create_file(credential, 0, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->comm_settings = comm;
    file->access_rights = access_rights;
    munit_assert_true(dfc_file_resize(credential, file, 4));
    memset(dfc_file_data(credential, file), fill, 4);

    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    session->emulator->selected_app_index = 0;
    return session;
}

static void read_four(DfcVirtualPiccSession* session, uint8_t expected) {
    const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 4, 0, 0, 0};
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read, sizeof(read), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 6);
    munit_assert_memory_equal(4, response, ((uint8_t[]){expected, expected, expected, expected}));
    munit_assert_uint8(response[4], ==, 0x91);
    munit_assert_uint8(response[5], ==, DFC_STATUS_OK);
}

static void set_native_authentication(
    DfcEmulator* emulator,
    DfcSecureMessaging* secure_messaging,
    uint8_t key_no) {
    memset(secure_messaging, 0, sizeof(*secure_messaging));
    secure_messaging->cipher = DFC_CMD_AUTHENTICATE_AES;
    emulator->secure_messaging = secure_messaging;
    emulator->auth_key_no = key_no;
}

static MunitResult
    test_effective_comm_requires_active_authentication(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator = {0};
    DfcFile file = {.comm_settings = DFC_COMM_ENCIPHERED, .access_rights = 0xEEEE};

    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_ENCIPHERED);

    DfcSecureMessaging secure_messaging;
    set_native_authentication(&emulator, &secure_messaging, 0);
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_PLAIN);
    return MUNIT_OK;
}

static MunitResult test_effective_comm_uses_the_authenticated_access_path(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator = {0};
    DfcSecureMessaging secure_messaging;
    DfcFile file = {.comm_settings = DFC_COMM_MAC, .access_rights = 0xE110};

    set_native_authentication(&emulator, &secure_messaging, 0);
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_PLAIN);

    emulator.auth_key_no = 1;
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_MAC);
    return MUNIT_OK;
}

static MunitResult
    test_effective_comm_handles_free_and_denied_paths(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator = {0};
    DfcSecureMessaging secure_messaging;
    set_native_authentication(&emulator, &secure_messaging, 3);

    DfcFile file = {.comm_settings = DFC_COMM_ENCIPHERED, .access_rights = 0xEFFF};
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_PLAIN);
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessWrite, file.comm_settings),
        ==,
        DFC_COMM_ENCIPHERED);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void setup_ev2_file(
    DfcEmulator* emulator,
    DfcCredential* credential,
    uint8_t comm,
    uint16_t access_rights,
    uint8_t key_no) {
    memset(emulator, 0, sizeof(*emulator));
    memset(credential, 0, sizeof(*credential));
    credential->num_apps = 1;
    credential->num_files = 1;
    credential->files[0].app_index = 0;
    credential->files[0].number = 1;
    credential->files[0].comm_settings = comm;
    credential->files[0].access_rights = access_rights;
    emulator->credential = credential;
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = key_no;
}

static MunitResult
    test_effective_comm_accepts_ev2_authentication(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator = {.ev2_session_active = true, .ev2_authenticated_key_no = 2};
    DfcFile file = {.comm_settings = DFC_COMM_ENCIPHERED, .access_rights = 0xE220};

    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_ENCIPHERED);
    emulator.ev2_authenticated_key_no = 0;
    munit_assert_uint8(
        dfc_emulator_file_effective_comm_settings(
            &emulator, &file, DfcFileAccessRead, file.comm_settings),
        ==,
        DFC_COMM_PLAIN);
    return MUNIT_OK;
}

static MunitResult
    test_ev2_prepare_uses_effective_comm(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator;
    DfcCredential credential;
    const uint8_t read[] = {DFC_CMD_READ_DATA, 1, 0, 0, 0, 0, 0, 0};
    uint8_t clear[sizeof(read)];
    size_t clear_len = 0;

    setup_ev2_file(&emulator, &credential, DFC_COMM_MAC, 0xE110, 0);
    munit_assert_int(
        dfc_ev2_prepare_command(&emulator, read, sizeof(read), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandPlainCounted);
    munit_assert_size(clear_len, ==, sizeof(read));
    munit_assert_memory_equal(sizeof(read), clear, read);

    emulator.ev2_authenticated_key_no = 1;
    munit_assert_int(
        dfc_ev2_prepare_command(&emulator, read, sizeof(read), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandInvalid);
    return MUNIT_OK;
}

static MunitResult
    test_update_record_uses_only_read_write_access(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator;
    DfcCredential credential;
    const uint8_t update[] = {DFC_CMD_UPDATE_RECORD, 1};
    uint8_t clear[sizeof(update)];
    size_t clear_len = 0;

    setup_ev2_file(&emulator, &credential, DFC_COMM_ENCIPHERED, 0xF0EF, 0);
    munit_assert_int(
        dfc_ev2_prepare_command(
            &emulator, update, sizeof(update), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandPlainCounted);

    credential.files[0].access_rights = 0xFE0F;
    munit_assert_int(
        dfc_ev2_prepare_command(
            &emulator, update, sizeof(update), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandInvalid);
    return MUNIT_OK;
}

static MunitResult test_ev2_free_only_reads_are_plain(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    static const struct {
        uint8_t comm;
        uint16_t access_rights;
        uint8_t fill;
    } cases[] = {
        {DFC_COMM_ENCIPHERED, 0xEEEE, 0x99},
        {DFC_COMM_MAC, 0xEEEE, 0x88},
        {DFC_COMM_ENCIPHERED, 0xE110, 0x77},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        DfcCredential credential;
        DfcVirtualPiccSession* session =
            open_file(&credential, cases[i].comm, cases[i].access_rights, cases[i].fill);
        session->emulator->ev2_session_active = true;
        session->emulator->ev2_authenticated_key_no = 0;
        session->emulator->ev2_command_counter = 7;
        read_four(session, cases[i].fill);
        munit_assert_uint16(session->emulator->ev2_command_counter, ==, 8);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult
    test_change_file_settings_uses_fixed_full_mode(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcEmulator emulator;
    DfcCredential credential;
    setup_ev2_file(&emulator, &credential, DFC_COMM_PLAIN, 0xEEE0, 0);
    memcpy(
        emulator.ev2_transaction_identifier,
        ((uint8_t[]){0xA1, 0xB2, 0xC3, 0xD4}),
        DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);

    const uint8_t settings[] = {DFC_COMM_MAC, 0xEE, 0xEE};
    uint8_t encrypted[DFC_AES_KEY_LENGTH];
    size_t encrypted_len = 0;
    munit_assert_true(dfc_ev2_encrypt_data(
        emulator.ev2_session_encryption_key,
        DfcEv2DirectionCommand,
        emulator.ev2_command_counter,
        emulator.ev2_transaction_identifier,
        settings,
        sizeof(settings),
        encrypted,
        sizeof(encrypted),
        &encrypted_len));
    munit_assert_size(encrypted_len, ==, sizeof(encrypted));

    uint8_t command[2 + sizeof(encrypted) + DFC_WIRE_MAC_LENGTH];
    command[0] = DFC_CMD_CHANGE_FILE_SETTINGS;
    command[1] = 1;
    memcpy(command + 2, encrypted, sizeof(encrypted));
    munit_assert_true(dfc_ev2_mac(
        emulator.ev2_session_mac_key,
        command[0],
        emulator.ev2_command_counter,
        emulator.ev2_transaction_identifier,
        command + 1,
        1 + sizeof(encrypted),
        NULL,
        0,
        command + 2 + sizeof(encrypted)));

    uint8_t clear[sizeof(command)];
    size_t clear_len = 0;
    munit_assert_int(
        dfc_ev2_prepare_command(
            &emulator, command, sizeof(command), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandFull);
    munit_assert_size(clear_len, ==, 2 + sizeof(settings));
    munit_assert_memory_equal(
        clear_len,
        clear,
        ((uint8_t[]){DFC_CMD_CHANGE_FILE_SETTINGS, 1, DFC_COMM_MAC, 0xEE, 0xEE}));

    credential.files[0].access_rights = 0xEEEE;
    const uint8_t plain[] = {DFC_CMD_CHANGE_FILE_SETTINGS, 1, DFC_COMM_MAC, 0xEE, 0xEE};
    munit_assert_int(
        dfc_ev2_prepare_command(&emulator, plain, sizeof(plain), clear, sizeof(clear), &clear_len),
        ==,
        DfcEv2CommandPlainCounted);
    return MUNIT_OK;
}

static MunitResult
    test_chained_effective_plain_counts_once(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_file(&credential, DFC_COMM_MAC, 0xEEEE, 0);
    DfcFile* file = dfc_credential_find_file_in_app(&credential, 0, 1);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&credential, file, 100));
    session->emulator->ev2_session_active = true;
    session->emulator->ev2_authenticated_key_no = 0;
    session->emulator->ev2_command_counter = 4;

    uint8_t expected[100];
    for(size_t i = 0; i < sizeof(expected); i++)
        expected[i] = (uint8_t)(i + 1);
    uint8_t first[6 + DFC_EV1_MAX_FRAME_PAYLOAD];
    first[0] = 0x90;
    first[1] = DFC_CMD_WRITE_DATA;
    first[2] = 0;
    first[3] = 0;
    first[4] = DFC_EV1_MAX_FRAME_PAYLOAD;
    memcpy(first + 5, ((uint8_t[]){1, 0, 0, 0, 100, 0, 0}), 7);
    memcpy(first + 12, expected, 52);
    first[sizeof(first) - 1] = 0;

    uint8_t response[16];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_CMD_ADDITIONAL_FRAME}));
    munit_assert_uint16(session->emulator->ev2_command_counter, ==, 4);

    uint8_t last[6 + 48] = {0x90, DFC_CMD_ADDITIONAL_FRAME, 0, 0, 48};
    memcpy(last + 5, expected + 52, 48);
    last[sizeof(last) - 1] = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, last, sizeof(last), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_uint16(session->emulator->ev2_command_counter, ==, 5);
    munit_assert_memory_equal(sizeof(expected), dfc_file_data(&credential, file), expected);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_ev2_direct_retry_preserves_overlapping_response(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_file(&credential, DFC_COMM_MAC, 0xE000, 0x69);
    DfcEmulator* emulator = session->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 0;
    emulator->ev2_command_counter = 4;

    uint8_t command[8 + DFC_WIRE_MAC_LENGTH] = {DFC_CMD_READ_DATA, 1, 0, 0, 0, 4, 0, 0};
    munit_assert_true(dfc_ev2_mac(
        emulator->ev2_session_mac_key,
        command[0],
        emulator->ev2_command_counter,
        emulator->ev2_transaction_identifier,
        command + 1,
        7,
        NULL,
        0,
        command + 8));

    uint8_t response[32];
    size_t response_len = SIZE_MAX;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 5);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1 + 4 + DFC_WIRE_MAC_LENGTH);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(4, response + 1, ((uint8_t[]){0x69, 0x69, 0x69, 0x69}));
    munit_assert_uint16(emulator->ev2_command_counter, ==, 5);
    munit_assert_memory_equal(
        sizeof(session->emulator->tx_buffer->data),
        session->emulator->tx_buffer->data,
        ((uint8_t[sizeof(session->emulator->tx_buffer->data)]){0}));
    munit_assert_size(session->emulator->tx_buffer->size_bytes, ==, 0);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}
#endif

static MunitResult test_ev1_e110_free_read_is_plain(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential;
    DfcVirtualPiccSession* session = open_file(&credential, DFC_COMM_ENCIPHERED, 0xE110, 0x77);
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    session->emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), NULL);
    munit_assert_not_null(session->emulator->secure_messaging);
    session->emulator->auth_key_no = 0;

    const uint8_t read[] = {0x90, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 4, 0, 0, 0};
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read, sizeof(read), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 14);
    munit_assert_memory_equal(4, response, ((uint8_t[]){0x77, 0x77, 0x77, 0x77}));
    munit_assert_uint8(response[12], ==, 0x91);
    munit_assert_uint8(response[13], ==, DFC_STATUS_OK);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/requires-active-authentication",
     test_effective_comm_requires_active_authentication,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/uses-authenticated-access-path",
     test_effective_comm_uses_the_authenticated_access_path,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/handles-free-and-denied-paths",
     test_effective_comm_handles_free_and_denied_paths,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev1-e110-free-read-is-plain",
     test_ev1_e110_free_read_is_plain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/accepts-ev2-authentication",
     test_effective_comm_accepts_ev2_authentication,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-prepare-uses-effective-comm",
     test_ev2_prepare_uses_effective_comm,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/update-record-uses-only-read-write-access",
     test_update_record_uses_only_read_write_access,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-free-only-reads-are-plain",
     test_ev2_free_only_reads_are_plain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/change-file-settings-uses-fixed-full-mode",
     test_change_file_settings_uses_fixed_full_mode,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/chained-effective-plain-counts-once",
     test_chained_effective_plain_counts_once,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/ev2-direct-retry-preserves-overlapping-response",
     test_ev2_direct_retry_preserves_overlapping_response,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_effective_comm",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
