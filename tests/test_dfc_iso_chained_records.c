// ReadRecords and WriteRecord use alternate instruction bytes when their
// logical APDU travels through ISO-DEP chaining. Exercise the encoder, native
// dispatcher, reader state machine, transaction view, and transport together.

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_reader.h"
#include "dfc_virtual_picc.h"
#include "dfc_ev2_crypto.h"

#include <string.h>

enum {
    ReadRecordsIso = 0xAB,
    WriteRecordIso = 0x8B,
    RecordFile = 0x0A,
};

static const uint8_t Aid[] = {0x01, 0x02, 0x03};
static const uint8_t WireAid[] = {0x03, 0x02, 0x01};

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* picc;
    DfcReaderSession reader;
    DfcFile* file;
} Fixture;

static void fixture_open(
    Fixture* fixture,
    size_t record_size,
    uint32_t max_records,
    uint32_t record_count) {
    memset(fixture, 0, sizeof(*fixture));
    dfc_credential_clear(&fixture->credential);
    const uint8_t uid[] = {0x04, 0x69, 0x01, 0x02, 0x03, 0x04, 0x05};
    memcpy(fixture->credential.uid, uid, sizeof(uid));
    fixture->credential.uid_len = sizeof(uid);
    fixture->credential.card.generation = DfcGenerationEv3;
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &fixture->credential, WireAid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    fixture->file = dfc_credential_create_file(&fixture->credential, 0, RecordFile);
    munit_assert_not_null(fixture->file);
    fixture->file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    fixture->file->comm_settings = DFC_COMM_PLAIN;
    fixture->file->access_rights = 0xEEEE;
    fixture->file->state.record.size = (uint32_t)record_size;
    fixture->file->state.record.max_records = max_records;
    fixture->file->state.record.count = record_count;
    munit_assert_true(
        dfc_file_resize(&fixture->credential, fixture->file, record_size * max_records));
    fixture->picc = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&fixture->reader);
}

static void fixture_close(Fixture* fixture) {
    dfc_virtual_picc_session_free(fixture->picc);
}

static void exchange_apdu(
    Fixture* fixture,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t* response,
    size_t* response_len) {
    *response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->picc, apdu, apdu_len, response, DFC_READER_MAX_RESPONSE, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_status(const uint8_t* response, size_t response_len, uint8_t status) {
    munit_assert_size(response_len, >=, 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, status);
}

static void select_application_raw(Fixture* fixture) {
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 3, 2, 1, 0};
    uint8_t response[DFC_READER_MAX_RESPONSE];
    size_t response_len;
    exchange_apdu(fixture, select, sizeof(select), response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);
}

static size_t build_record_apdu(
    uint8_t instruction,
    uint8_t file_no,
    uint32_t first,
    uint32_t count,
    const uint8_t* data,
    size_t data_len,
    uint8_t* apdu) {
    size_t command_len = 7 + data_len;
    munit_assert_size(command_len, <=, DFC_COMMAND_MAX_DATA);
    apdu[0] = 0x90;
    apdu[1] = instruction;
    apdu[2] = 0;
    apdu[3] = 0;
    apdu[4] = (uint8_t)command_len;
    apdu[5] = file_no;
    apdu[6] = (uint8_t)first;
    apdu[7] = (uint8_t)(first >> 8);
    apdu[8] = (uint8_t)(first >> 16);
    apdu[9] = (uint8_t)count;
    apdu[10] = (uint8_t)(count >> 8);
    apdu[11] = (uint8_t)(count >> 16);
    if(data_len) memcpy(apdu + 12, data, data_len);
    apdu[12 + data_len] = 0;
    return 13 + data_len;
}

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
        exchange_apdu(fixture, request, request_len, response, &response_len);
        answer = response;
    }
    return status;
}

static DfcReaderStatus
    send_reader(Fixture* fixture, const DfcCommand* command, DfcReaderExchange* exchange) {
    const DfcReaderOptions options = {.comm_mode = DFC_COMM_PLAIN};
    munit_assert_int(
        dfc_reader_exchange_begin(
            exchange, &fixture->reader, DfcReaderFramingIso7816, command, &options),
        ==,
        DfcReaderOk);
    return run_reader(fixture, exchange);
}

static MunitResult test_raw_dispatch_and_errors(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    fixture_open(&fixture, 4, 4, 2);
    uint8_t* stored = dfc_file_data(&fixture.credential, fixture.file);
    const uint8_t original[] = {0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24};
    memcpy(stored, original, sizeof(original));
    select_application_raw(&fixture);

    uint8_t apdu[DFC_COMMAND_MAX_APDU];
    uint8_t response[DFC_READER_MAX_RESPONSE];
    size_t response_len;
    size_t apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 2, NULL, 0, apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);
    munit_assert_size(response_len, ==, sizeof(original) + 2);
    munit_assert_memory_equal(sizeof(original), response, original);

    const uint8_t appended[] = {0x31, 0x32, 0x33, 0x34};
    apdu_len = build_record_apdu(
        WriteRecordIso, RecordFile, 0, sizeof(appended), appended, sizeof(appended), apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);

    // Record writes stay behind the transaction snapshot until commit.
    apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 2, NULL, 0, apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);
    munit_assert_size(response_len, ==, sizeof(original) + 2);
    munit_assert_memory_equal(sizeof(original), response, original);

    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    exchange_apdu(&fixture, commit, sizeof(commit), response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);
    const uint8_t committed[] = {
        0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34};
    apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 0, NULL, 0, apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_OK);
    munit_assert_size(response_len, ==, sizeof(committed) + 2);
    munit_assert_memory_equal(sizeof(committed), response, committed);

    const uint8_t short_read[] = {0x90, ReadRecordsIso, 0, 0, 6, RecordFile, 0, 0, 0, 1, 0, 0, 0};
    exchange_apdu(&fixture, short_read, sizeof(short_read), response, &response_len);
    assert_status(response, response_len, DFC_STATUS_LENGTH_ERROR);
    const uint8_t short_write[] = {0x90, WriteRecordIso, 0, 0, 6, RecordFile, 0, 0, 0, 1, 0, 0, 0};
    exchange_apdu(&fixture, short_write, sizeof(short_write), response, &response_len);
    assert_status(response, response_len, DFC_STATUS_LENGTH_ERROR);

    apdu_len = build_record_apdu(ReadRecordsIso, 0x1F, 0, 1, NULL, 0, apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_FILE_NOT_FOUND);
    const uint8_t outside[] = {0xAA};
    apdu_len = build_record_apdu(WriteRecordIso, RecordFile, 4, 1, outside, sizeof(outside), apdu);
    exchange_apdu(&fixture, apdu, apdu_len, response, &response_len);
    assert_status(response, response_len, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_uint32(fixture.file->state.record.count, ==, 3);
    munit_assert_memory_equal(sizeof(committed), stored, committed);

    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_reader_round_trip_variants(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(size_t iso_chaining = 0; iso_chaining <= 1; iso_chaining++) {
        Fixture fixture;
        fixture_open(&fixture, 8, 3, 0);
        DfcCommand command;
        DfcReaderExchange exchange;
        munit_assert_int(dfc_command_select_application(&command, Aid, NULL), ==, DfcCommandOk);
        munit_assert_int(send_reader(&fixture, &command, &exchange), ==, DfcReaderOk);

        const uint8_t record[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
        munit_assert_int(
            dfc_command_write_record(
                &command, RecordFile, 0, record, sizeof(record), iso_chaining != 0),
            ==,
            DfcCommandOk);
        munit_assert_uint8(command.ins, ==, iso_chaining ? WriteRecordIso : DFC_CMD_WRITE_RECORD);
        munit_assert_int(send_reader(&fixture, &command, &exchange), ==, DfcReaderOk);
        munit_assert_int(dfc_command_commit_transaction(&command), ==, DfcCommandOk);
        munit_assert_int(send_reader(&fixture, &command, &exchange), ==, DfcReaderOk);

        munit_assert_int(
            dfc_command_read_records(&command, RecordFile, 0, 1, iso_chaining != 0),
            ==,
            DfcCommandOk);
        munit_assert_uint8(command.ins, ==, iso_chaining ? ReadRecordsIso : DFC_CMD_READ_RECORDS);
        munit_assert_int(send_reader(&fixture, &command, &exchange), ==, DfcReaderOk);
        size_t result_len = 0;
        const uint8_t* result = dfc_reader_result_data(&exchange, &result_len);
        munit_assert_size(result_len, ==, sizeof(record));
        munit_assert_memory_equal(sizeof(record), result, record);
        fixture_close(&fixture);
    }
    return MUNIT_OK;
}

static void activate_iso_dep(Fixture* fixture) {
    const uint8_t rats[] = {0xE0, 0x80};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->picc, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >, 0);
}

static size_t exchange_iso_dep_command(
    Fixture* fixture,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t* complete,
    size_t complete_capacity,
    size_t* request_frames,
    size_t* response_frames) {
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    size_t offset = 0;
    *request_frames = 0;
    *response_frames = 0;

    while(offset < apdu_len) {
        size_t chunk = apdu_len - offset;
        if(chunk > 40) chunk = 40;
        bool more = offset + chunk < apdu_len;
        uint8_t frame[1 + 40];
        frame[0] = (uint8_t)(0x02 | (fixture->picc->expected_pcd_sequence & 1));
        if(more) frame[0] |= 0x10;
        memcpy(frame + 1, apdu + offset, chunk);
        DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->picc, frame, chunk + 1, response, sizeof(response), &response_len);
        if(status != DfcVirtualPiccStatusOk)
            munit_logf(
                MUNIT_LOG_WARNING, "frame offset %zu/%zu status %d", offset, apdu_len, status);
        munit_assert_int(status, ==, DfcVirtualPiccStatusOk);
        (*request_frames)++;
        offset += chunk;
        if(more) {
            munit_assert_size(response_len, ==, 1);
            munit_assert_uint8(response[0] & 0xE0, ==, 0xA0);
        }
    }

    size_t complete_len = 0;
    for(;;) {
        munit_assert_size(response_len, >=, 1);
        munit_assert_uint8(response[0] & 0xC0, ==, 0x00);
        size_t inf_len = response_len - 1;
        munit_assert_size(inf_len, <=, complete_capacity - complete_len);
        memcpy(complete + complete_len, response + 1, inf_len);
        complete_len += inf_len;
        (*response_frames)++;
        if((response[0] & 0x10) == 0) break;
        uint8_t ack = (uint8_t)(0xA2 | (fixture->picc->picc_sequence & 1));
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                fixture->picc, &ack, 1, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
    }
    return complete_len;
}

static MunitResult
    test_iso_dep_transport_continuations(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    fixture_open(&fixture, 160, 3, 1);
    uint8_t first_record[160];
    uint8_t second_record[160];
    for(size_t i = 0; i < sizeof(first_record); i++) {
        first_record[i] = (uint8_t)i;
        second_record[i] = (uint8_t)(0xF0 ^ i);
    }
    memcpy(dfc_file_data(&fixture.credential, fixture.file), first_record, sizeof(first_record));
    activate_iso_dep(&fixture);

    uint8_t complete[DFC_READER_MAX_RESPONSE];
    size_t request_frames;
    size_t response_frames;
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 3, 2, 1, 0};
    size_t complete_len = exchange_iso_dep_command(
        &fixture,
        select,
        sizeof(select),
        complete,
        sizeof(complete),
        &request_frames,
        &response_frames);
    assert_status(complete, complete_len, DFC_STATUS_OK);

    uint8_t apdu[DFC_COMMAND_MAX_APDU];
    size_t apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 1, NULL, 0, apdu);
    complete_len = exchange_iso_dep_command(
        &fixture, apdu, apdu_len, complete, sizeof(complete), &request_frames, &response_frames);
    munit_assert_size(request_frames, ==, 1);
    munit_assert_size(response_frames, >, 1);
    assert_status(complete, complete_len, DFC_STATUS_OK);
    munit_assert_size(complete_len, ==, sizeof(first_record) + 2);
    munit_assert_memory_equal(sizeof(first_record), complete, first_record);

    apdu_len = build_record_apdu(
        WriteRecordIso,
        RecordFile,
        0,
        sizeof(second_record),
        second_record,
        sizeof(second_record),
        apdu);
    complete_len = exchange_iso_dep_command(
        &fixture, apdu, apdu_len, complete, sizeof(complete), &request_frames, &response_frames);
    munit_assert_size(request_frames, >, 1);
    munit_assert_size(response_frames, ==, 1);
    assert_status(complete, complete_len, DFC_STATUS_OK);

    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    complete_len = exchange_iso_dep_command(
        &fixture,
        commit,
        sizeof(commit),
        complete,
        sizeof(complete),
        &request_frames,
        &response_frames);
    assert_status(complete, complete_len, DFC_STATUS_OK);

    apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 1, NULL, 0, apdu);
    complete_len = exchange_iso_dep_command(
        &fixture, apdu, apdu_len, complete, sizeof(complete), &request_frames, &response_frames);
    assert_status(complete, complete_len, DFC_STATUS_OK);
    munit_assert_size(complete_len, ==, sizeof(second_record) + 2);
    munit_assert_memory_equal(sizeof(second_record), complete, second_record);

    // Reading the complete record set must preserve the file's supported extent.
    apdu_len = build_record_apdu(ReadRecordsIso, RecordFile, 0, 0, NULL, 0, apdu);
    complete_len = exchange_iso_dep_command(
        &fixture, apdu, apdu_len, complete, sizeof(complete), &request_frames, &response_frames);
    assert_status(complete, complete_len, DFC_STATUS_OK);
    munit_assert_size(complete_len, ==, sizeof(first_record) + sizeof(second_record) + 2);
    munit_assert_memory_equal(sizeof(first_record), complete, first_record);
    munit_assert_memory_equal(
        sizeof(second_record), complete + sizeof(first_record), second_record);

    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_full_extent(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    fixture_open(&fixture, DFC_MAX_FILE_DATA, 1, 0);
    activate_iso_dep(&fixture);
    uint8_t complete[DFC_EMULATOR_CHAIN_BUFFER_SIZE];
    size_t requests, responses;
    const uint8_t select[] = {0x90, DFC_CMD_SELECT_APPLICATION, 0, 0, 3, 3, 2, 1, 0};
    size_t length = exchange_iso_dep_command(
        &fixture, select, sizeof(select), complete, sizeof(complete), &requests, &responses);
    assert_status(complete, length, DFC_STATUS_OK);
    uint8_t command[8 + DFC_MAX_FILE_DATA] = {WriteRecordIso, RecordFile};
    command[5] = (uint8_t)DFC_MAX_FILE_DATA;
    command[6] = (uint8_t)(DFC_MAX_FILE_DATA >> 8);
    command[7] = (uint8_t)(DFC_MAX_FILE_DATA >> 16);
    for(size_t i = 0; i < DFC_MAX_FILE_DATA; i++)
        command[8 + i] = (uint8_t)i;
    length = exchange_iso_dep_command(
        &fixture, command, sizeof(command), complete, sizeof(complete), &requests, &responses);
    munit_assert_size(requests, >, 1);
    munit_assert_size(length, ==, 1);
    munit_assert_uint8(complete[0], ==, DFC_STATUS_OK);
    const uint8_t commit[] = {0x90, DFC_CMD_COMMIT_TRANSACTION, 0, 0, 0};
    length = exchange_iso_dep_command(
        &fixture, commit, sizeof(commit), complete, sizeof(complete), &requests, &responses);
    assert_status(complete, length, DFC_STATUS_OK);
    uint8_t read[13];
    build_record_apdu(ReadRecordsIso, RecordFile, 0, 0, NULL, 0, read);
    length = exchange_iso_dep_command(
        &fixture, read, sizeof(read), complete, sizeof(complete), &requests, &responses);
    assert_status(complete, length, DFC_STATUS_OK);
    munit_assert_size(length, ==, DFC_MAX_FILE_DATA + 2);
    munit_assert_memory_equal(DFC_MAX_FILE_DATA, complete, command + 8);
    munit_assert_size(fixture.picc->emulator->pending_chain_len, ==, 0);
    uint8_t small[1];
    size_t retry_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.picc, read, sizeof(read), small, sizeof(small), &retry_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(retry_len, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.picc, read, sizeof(read), complete, sizeof(complete), &retry_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_status(complete, retry_len, DFC_STATUS_OK);
    munit_assert_size(retry_len, ==, DFC_MAX_FILE_DATA + 2);
    munit_assert_memory_equal(DFC_MAX_FILE_DATA, complete, command + 8);
    munit_assert_size(fixture.picc->emulator->pending_chain_len, ==, 0);
    fixture_close(&fixture);
    return MUNIT_OK;
}

static MunitResult test_raw_emulator_response(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    fixture_open(&fixture, 16, 1, 1);
    select_application_raw(&fixture);
    const uint8_t command[] = {ReadRecordsIso, RecordFile, 0, 0, 0, 1, 0, 0};
    DfcByteBuf output = {0};
    munit_assert_true(dfc_emulator_handle_command(
        fixture.picc->emulator, command, sizeof(command), &output, NULL));
    munit_assert_size(dfc_bytebuf_get_size_bytes(&output), ==, 17);
    munit_assert_uint8(dfc_bytebuf_get_byte(&output, 0), ==, DFC_STATUS_OK);
    fixture.file->state.record.size = DFC_MAX_FILE_DATA;
    munit_assert_true(dfc_file_resize(&fixture.credential, fixture.file, DFC_MAX_FILE_DATA));
    dfc_bytebuf_reset(&output);
    munit_assert_true(dfc_emulator_handle_command(
        fixture.picc->emulator, command, sizeof(command), &output, NULL));
    munit_assert_size(dfc_bytebuf_get_size_bytes(&output), ==, 1);
    munit_assert_uint8(dfc_bytebuf_get_byte(&output, 0), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_size(fixture.picc->emulator->pending_chain_len, ==, 0);
    fixture_close(&fixture);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static MunitResult test_retired_request_retry(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    fixture_open(&fixture, 160, 1, 0);
    select_application_raw(&fixture);
    activate_iso_dep(&fixture);
    fixture.file->comm_settings = DFC_COMM_MAC;
    fixture.file->access_rights = 0;
    DfcEmulator* emulator = fixture.picc->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 0;
    // A valid final command whose response protection cannot advance the counter.
    emulator->ev2_command_counter = UINT16_MAX;
    uint8_t command[8 + 160 + DFC_WIRE_MAC_LENGTH] = {WriteRecordIso, RecordFile};
    command[5] = 160;
    memset(command + 8, 0x55, 160);
    munit_assert_true(dfc_ev2_mac(
        emulator->ev2_session_mac_key,
        command[0],
        emulator->ev2_command_counter,
        emulator->ev2_transaction_identifier,
        command + 1,
        sizeof(command) - 1 - DFC_WIRE_MAC_LENGTH,
        NULL,
        0,
        command + sizeof(command) - DFC_WIRE_MAC_LENGTH));
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    uint8_t frame[41];
    size_t response_len = 0, final_len = 0;
    for(size_t offset = 0; offset < sizeof(command);) {
        size_t chunk = sizeof(command) - offset;
        if(chunk > 40) chunk = 40;
        bool more = offset + chunk < sizeof(command);
        frame[0] = (uint8_t)(0x02 | fixture.picc->expected_pcd_sequence | (more ? 0x10 : 0));
        memcpy(frame + 1, command + offset, chunk);
        DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_frame_exchange(
            fixture.picc, frame, chunk + 1, response, sizeof(response), &response_len);
        munit_assert_int(
            status, ==, more ? DfcVirtualPiccStatusOk : DfcVirtualPiccStatusProtocolError);
        offset += chunk;
        final_len = chunk + 1;
    }
    munit_assert_null(emulator->command_chain);
    munit_assert_size(fixture.picc->pending_command_len, ==, 0);
    // Retrying the final I-block must not resurrect a length without its storage.
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture.picc, frame, final_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    fixture_close(&fixture);
    return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/retired-request-retry", test_retired_request_retry, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/raw-emulator-response", test_raw_emulator_response, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/full-extent", test_full_extent, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/raw-dispatch-and-errors",
     test_raw_dispatch_and_errors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-round-trip-variants",
     test_reader_round_trip_variants,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-transport-continuations",
     test_iso_dep_transport_continuations,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_iso_chained_records", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
