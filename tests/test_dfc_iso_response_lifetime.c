#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_iso_dep.h"

#include <string.h>

enum {
    RecordFile = 0x0F,
    RecordByte = 0x5A,
    UntouchedOutputByte = 0xA5,
    ReaderFrameSize256 = 0x80,
    RecordBelowInlineLimit = DFC_WORKER_MAX_BUFFER_SIZE / 2,
    RecordAboveInlineLimit = DFC_WORKER_MAX_BUFFER_SIZE + 1,
    HalfFileCapacity = DFC_MAX_FILE_DATA / 2,
};

enum {
    InvalidOffset,
    InvalidLength,
    InvalidPrefix,
    InvalidCachedBlock,
    InvalidCaseCount,
};

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
} Fixture;

static void open_record(Fixture* fixture, size_t length) {
    load_standard_credential(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_find_file_in_app(&fixture->credential, 0, RecordFile);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->record_size = (uint32_t)length;
    file->record_count = file->max_records = 1;
    munit_assert_true(dfc_file_resize(&fixture->credential, file, length));
    memset(dfc_file_data(&fixture->credential, file), RecordByte, length);
    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t select[] = {DFC_CMD_SELECT_APPLICATION, 0x4F, 0x49, 0xD3};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->session, select, sizeof(select), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
}

static const uint8_t ReadRecord[] = {DFC_CMD_READ_RECORDS_ISO, RecordFile, 0, 0, 0, 1, 0, 0};

static void begin_response(Fixture* fixture, uint8_t cid) {
    const uint8_t rats[] = {DFC_ISO_DEP_RATS, (uint8_t)(ReaderFrameSize256 | cid)};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    uint8_t frame[2 + sizeof(ReadRecord)];
    size_t prefix = cid ? 2 : 1;
    frame[0] = DFC_ISO_DEP_I_BLOCK | (cid ? DFC_ISO_DEP_CID : 0);
    if(cid) frame[1] = cid;
    memcpy(frame + prefix, ReadRecord, sizeof(ReadRecord));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session,
            frame,
            prefix + sizeof(ReadRecord),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(response[0] & DFC_ISO_DEP_MORE, ==, DFC_ISO_DEP_MORE);
    munit_assert_size(fixture->session->pending_response_len, >, 0);
}

static void assert_retired(const DfcVirtualPiccSession* session) {
    munit_assert_size(session->pending_response_len, ==, 0);
    munit_assert_size(session->pending_response_offset, ==, 0);
    munit_assert_size(session->pending_response_prefix_len, ==, 0);
    munit_assert_size(session->last_picc_block_len, ==, 0);
}

static void reject_frame(Fixture* fixture, uint8_t pcb, uint8_t cid) {
    uint8_t frame[] = {(uint8_t)(pcb | (cid ? DFC_ISO_DEP_CID : 0)), cid};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE], unchanged[sizeof(response)];
    memset(response, UntouchedOutputByte, sizeof(response));
    memcpy(unchanged, response, sizeof(response));
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session, frame, cid ? 2 : 1, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    munit_assert_memory_equal(sizeof(response), response, unchanged);
    assert_retired(fixture->session);
}

static MunitResult test_reset_during_response(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const size_t lengths[] = {
        RecordBelowInlineLimit, RecordAboveInlineLimit, HalfFileCapacity, DFC_MAX_FILE_DATA};
    const uint8_t acknowledgements[] = {
        DFC_ISO_DEP_R_BLOCK,
        DFC_ISO_DEP_R_BLOCK | DFC_ISO_DEP_SEQUENCE_BIT,
        DFC_ISO_DEP_R_BLOCK | DFC_ISO_DEP_R_NAK,
        DFC_ISO_DEP_R_BLOCK | DFC_ISO_DEP_R_NAK | DFC_ISO_DEP_SEQUENCE_BIT};
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(uint8_t cid = 0; cid <= 1; cid++) {
            for(size_t ack = 0; ack < sizeof(acknowledgements); ack++) {
                Fixture fixture;
                open_record(&fixture, lengths[i]);
                begin_response(&fixture, cid);
                // The emulator reset invalidates a lent buffer, including small replies.
                dfc_emulator_reset_session(fixture.session->emulator);
                reject_frame(&fixture, acknowledgements[ack], cid);
                reject_frame(&fixture, acknowledgements[ack], cid);
                dfc_virtual_picc_session_free(fixture.session);
            }
        }
    }
    return MUNIT_OK;
}

static MunitResult test_reset_during_direct_retry(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const size_t lengths[] = {RecordBelowInlineLimit, HalfFileCapacity};
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        Fixture fixture;
        open_record(&fixture, lengths[i]);
        uint8_t response[DFC_EMULATOR_CHAIN_BUFFER_SIZE];
        size_t response_len = 0;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                fixture.session, ReadRecord, sizeof(ReadRecord), response, 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        dfc_emulator_reset_session(fixture.session->emulator);
        memset(response, UntouchedOutputByte, sizeof(response));
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                fixture.session,
                ReadRecord,
                sizeof(ReadRecord),
                response,
                sizeof(response),
                &response_len),
            ==,
            DfcVirtualPiccStatusProtocolError);
        munit_assert_size(response_len, ==, 0);
        for(size_t j = 0; j < sizeof(response); j++)
            munit_assert_uint8(response[j], ==, UntouchedOutputByte);
        assert_retired(fixture.session);
        dfc_virtual_picc_session_free(fixture.session);
    }
    return MUNIT_OK;
}

static MunitResult test_invalid_response_bounds(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(size_t invalid = 0; invalid < InvalidCaseCount; invalid++) {
        Fixture fixture;
        open_record(&fixture, HalfFileCapacity);
        begin_response(&fixture, 0);
        switch(invalid) {
        case InvalidOffset:
            fixture.session->pending_response_offset = fixture.session->pending_response_len + 1;
            break;
        case InvalidLength:
            fixture.session->pending_response_len = SIZE_MAX;
            fixture.session->emulator->pending_chain_len = SIZE_MAX;
            break;
        case InvalidPrefix:
            fixture.session->pending_response_prefix_len =
                sizeof(fixture.session->pending_response_prefix) + 1;
            break;
        case InvalidCachedBlock:
            fixture.session->last_picc_block_len = sizeof(fixture.session->last_picc_block) + 1;
            break;
        }
        reject_frame(&fixture, DFC_ISO_DEP_R_BLOCK | DFC_ISO_DEP_SEQUENCE_BIT, 0);
        dfc_virtual_picc_session_free(fixture.session);
    }
    return MUNIT_OK;
}

static MunitResult test_inline_capacity_retry(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    open_record(&fixture, RecordBelowInlineLimit);
    const uint8_t version[] = {DFC_CMD_GET_VERSION};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, version, sizeof(version), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, version, sizeof(version), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >, 1);
    munit_assert_uint8(response[0], ==, DFC_CMD_ADDITIONAL_FRAME);
    assert_retired(fixture.session);
    dfc_virtual_picc_session_free(fixture.session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/reset-during-response", test_reset_during_response, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/reset-during-direct-retry",
     test_reset_during_direct_retry,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/invalid-response-bounds",
     test_invalid_response_bounds,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/inline-capacity-retry", test_inline_capacity_retry, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};
static const MunitSuite suite =
    {"/dfc_iso_response_lifetime", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
