// Secure-messaging parity for the ISO-chained record instruction variants.

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_reader.h"
#include "dfc_virtual_picc.h"

#include <string.h>

enum {
    RecordFile = 0x0A
};

static const uint8_t Aid[] = {0x01, 0x02, 0x03};
static const uint8_t WireAid[] = {0x03, 0x02, 0x01};
static const uint8_t SessionKey[DFC_AES_KEY_LENGTH] = {
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
    0x1F,
};

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* picc;
    DfcReaderSession reader;
} Fixture;

static DfcReaderStatus run_reader(Fixture* fixture, DfcReaderExchange* exchange) {
    uint8_t request[DFC_COMMAND_MAX_APDU];
    uint8_t response[DFC_READER_MAX_RESPONSE];
    size_t request_len = 0;
    size_t response_len = 0;
    const uint8_t* answer = NULL;
    DfcReaderStatus status;
    while((status = dfc_reader_step(
               exchange, answer, response_len, request, sizeof(request), &request_len)) ==
          DfcReaderPending) {
        response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                fixture->picc, request, request_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        answer = response;
    }
    return status;
}

static DfcReaderStatus send_reader(
    Fixture* fixture,
    const DfcCommand* command,
    uint8_t comm,
    DfcReaderExchange* exchange) {
    const DfcReaderOptions options = {.comm_mode = comm};
    munit_assert_int(
        dfc_reader_exchange_begin(
            exchange, &fixture->reader, DfcReaderFramingIso7816, command, &options),
        ==,
        DfcReaderOk);
    return run_reader(fixture, exchange);
}

static void fixture_open(Fixture* fixture, uint8_t comm) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    const uint8_t uid[] = {0x04, 0x69, 0x11, 0x12, 0x13, 0x14, 0x15};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    fixture->credential.card.generation = DfcGenerationEv3;
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &fixture->credential, WireAid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    DfcFile* file = dfc_credential_create_file(&fixture->credential, 0, RecordFile);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = comm;
    file->access_rights = 0x0000;
    file->state.record.size = 16;
    file->state.record.max_records = 16;
    munit_assert_true(dfc_file_resize(&fixture->credential, file, 256));

    fixture->picc = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&fixture->reader);

    DfcCommand select;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_select_application(&select, Aid, NULL), ==, DfcCommandOk);
    munit_assert_int(send_reader(fixture, &select, DFC_COMM_PLAIN, &exchange), ==, DfcReaderOk);
}

static void begin_ev1_session(Fixture* fixture) {
    fixture->picc->emulator->secure_messaging =
        dfc_secure_messaging_alloc(DFC_CMD_AUTHENTICATE_AES, SessionKey, sizeof(SessionKey), NULL);
    munit_assert_not_null(fixture->picc->emulator->secure_messaging);
    munit_assert_true(dfc_secure_messaging_init(
        fixture->picc->emulator->secure_messaging,
        DFC_CMD_AUTHENTICATE_AES,
        SessionKey,
        sizeof(SessionKey),
        NULL));
    fixture->picc->emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    fixture->picc->emulator->auth_key_no = 0;

    munit_assert_true(dfc_secure_messaging_init(
        &fixture->reader.sm, DFC_CMD_AUTHENTICATE_AES, SessionKey, sizeof(SessionKey), NULL));
    fixture->reader.sm.pcd = true;
    fixture->reader.auth_mode = DFC_CMD_AUTHENTICATE_AES;
    fixture->reader.key_no = 0;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void begin_ev2_session(Fixture* fixture) {
    static const uint8_t transaction_id[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH] = {
        0x21, 0x22, 0x23, 0x24};
    DfcEmulator* emulator = fixture->picc->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 0;
    emulator->ev2_command_counter = 0;
    memcpy(emulator->ev2_transaction_identifier, transaction_id, sizeof(transaction_id));
    memcpy(emulator->ev2_session_encryption_key, SessionKey, sizeof(SessionKey));
    memcpy(emulator->ev2_session_mac_key, SessionKey, sizeof(SessionKey));

    fixture->reader.auth_mode = DFC_READER_AUTH_EV2;
    fixture->reader.key_no = 0;
    fixture->reader.ev2_command_counter = 0;
    memcpy(fixture->reader.ev2_transaction_identifier, transaction_id, sizeof(transaction_id));
    memcpy(fixture->reader.ev2_encryption_key, SessionKey, sizeof(SessionKey));
    memcpy(fixture->reader.ev2_mac_key, SessionKey, sizeof(SessionKey));
}
#endif

static void assert_round_trip(
    Fixture* fixture,
    uint8_t comm,
    uint8_t marker,
    size_t record_len,
    size_t count) {
    uint8_t record[160];
    munit_assert_size(record_len, <=, sizeof(record));
    for(size_t i = 0; i < record_len; i++)
        record[i] = (uint8_t)(marker + i);

    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_command_write_record(&command, RecordFile, 0, record, record_len, true),
        ==,
        DfcCommandOk);
    munit_assert_uint8(command.ins, ==, DFC_CMD_WRITE_RECORD_ISO);
    DfcReaderStatus status = DfcReaderOk;
    DfcCommand commit;
    munit_assert_int(dfc_command_commit_transaction(&commit), ==, DfcCommandOk);
    for(size_t i = 0; i < count; i++) {
        status = send_reader(fixture, &command, comm, &exchange);
        munit_assert_int(status, ==, DfcReaderOk);
        if(i + 1 < count)
            munit_assert_int(
                send_reader(fixture, &commit, DFC_COMM_PLAIN, &exchange), ==, DfcReaderOk);
    }
    if(status != DfcReaderOk) {
        munit_logf(
            MUNIT_LOG_WARNING,
            "WriteRecord mode %u returned reader %d / card %02X",
            comm,
            status,
            dfc_reader_result_status(&exchange));
    }
    munit_assert_int(status, ==, DfcReaderOk);

    munit_assert_int(dfc_command_commit_transaction(&command), ==, DfcCommandOk);
    munit_assert_int(send_reader(fixture, &command, DFC_COMM_PLAIN, &exchange), ==, DfcReaderOk);

    munit_assert_int(dfc_command_read_records(&command, RecordFile, 0, 0, true), ==, DfcCommandOk);
    munit_assert_uint8(command.ins, ==, DFC_CMD_READ_RECORDS_ISO);
    munit_assert_int(send_reader(fixture, &command, comm, &exchange), ==, DfcReaderOk);
    size_t result_len = 0;
    const uint8_t* result = dfc_reader_result_data(&exchange, &result_len);
    munit_assert_size(result_len, ==, count * record_len);
    for(size_t i = 0; i < count; i++)
        munit_assert_memory_equal(record_len, result + i * record_len, record);
}

static MunitResult test_ev1_secure_modes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t modes[] = {DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    for(size_t i = 0; i < sizeof(modes); i++) {
        Fixture fixture;
        fixture_open(&fixture, modes[i]);
        begin_ev1_session(&fixture);
        assert_round_trip(&fixture, modes[i], (uint8_t)(0x40 + 0x20 * i), 16, 10);
        dfc_virtual_picc_session_free(fixture.picc);
    }
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static MunitResult test_ev2_secure_modes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t modes[] = {DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    for(size_t i = 0; i < sizeof(modes); i++) {
        Fixture fixture;
        fixture_open(&fixture, modes[i]);
        begin_ev2_session(&fixture);
        assert_round_trip(&fixture, modes[i], (uint8_t)(0x80 + 0x20 * i), 16, 10);
        munit_assert_uint16(fixture.reader.ev2_command_counter, ==, 21);
        munit_assert_uint16(fixture.picc->emulator->ev2_command_counter, ==, 21);
        dfc_virtual_picc_session_free(fixture.picc);
    }
    return MUNIT_OK;
}
#endif

static MunitResult test_large_secure_write(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t modes[] = {DFC_COMM_MAC, DFC_COMM_ENCIPHERED};
    for(size_t ev2 = 0; ev2 < 2; ev2++) {
#if !DFC_ENABLE_EV2_SECURE_MESSAGING
        if(ev2) continue;
#endif
        for(size_t mode = 0; mode < sizeof(modes); mode++) {
            Fixture fixture;
            fixture_open(&fixture, modes[mode]);
            DfcFile* file = dfc_credential_find_file_in_app(&fixture.credential, 0, RecordFile);
            file->state.record.size = 160;
            file->state.record.max_records = 3;
            munit_assert_true(dfc_file_resize(&fixture.credential, file, 480));
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            if(ev2)
                begin_ev2_session(&fixture);
            else
#endif
                begin_ev1_session(&fixture);
            assert_round_trip(&fixture, modes[mode], 0x31, 160, 1);
            dfc_virtual_picc_session_free(fixture.picc);
        }
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/large-secure-write", test_large_secure_write, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ev1-secure-modes", test_ev1_secure_modes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/ev2-secure-modes", test_ev2_secure_modes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_iso_chained_records_secure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
