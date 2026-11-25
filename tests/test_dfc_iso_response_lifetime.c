#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
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
    InvalidOversizedLength,
    InvalidShortChainLength,
    InvalidResponseLengthMismatch,
    InvalidOwnership,
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
    file->state.record.size = (uint32_t)length;
    file->state.record.count = file->state.record.max_records = 1;
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

static void exchange_read_record_frame(
    Fixture* fixture,
    uint8_t cid,
    uint8_t sequence,
    uint8_t* response,
    size_t* response_len) {
    uint8_t frame[2 + sizeof(ReadRecord)];
    size_t prefix = cid ? 2 : 1;
    frame[0] = (uint8_t)(DFC_ISO_DEP_I_BLOCK | (sequence & DFC_ISO_DEP_SEQUENCE_BIT) |
                         (cid ? DFC_ISO_DEP_CID : 0));
    if(cid) frame[1] = cid;
    memcpy(frame + prefix, ReadRecord, sizeof(ReadRecord));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session,
            frame,
            prefix + sizeof(ReadRecord),
            response,
            DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE,
            response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void assert_record_block(const uint8_t* block, size_t block_len, uint8_t cid) {
    size_t prefix = cid ? 2 : 1;
    munit_assert_size(block_len, >, prefix + 1);
    munit_assert_uint8(block[prefix], ==, DFC_STATUS_OK);
    for(size_t i = prefix + 1; i < block_len; i++)
        munit_assert_uint8(block[i], ==, RecordByte);
}

static void begin_response_capture(
    Fixture* fixture,
    uint8_t cid,
    uint8_t* first_block,
    size_t* first_block_len) {
    const uint8_t rats[] = {DFC_ISO_DEP_RATS, (uint8_t)(ReaderFrameSize256 | cid)};
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    exchange_read_record_frame(
        fixture, cid, fixture->session->expected_pcd_sequence, response, &response_len);
    munit_assert_uint8(response[0] & DFC_ISO_DEP_MORE, ==, DFC_ISO_DEP_MORE);
    munit_assert_size(fixture->session->pending_response_len, >, 0);
    if(first_block) memcpy(first_block, response, response_len);
    if(first_block_len) *first_block_len = response_len;
}

static void begin_response(Fixture* fixture, uint8_t cid) {
    begin_response_capture(fixture, cid, NULL, NULL);
}

static void assert_retired(const DfcVirtualPiccSession* session) {
    munit_assert_size(session->pending_response_len, ==, 0);
    munit_assert_size(session->pending_response_offset, ==, 0);
    munit_assert_size(session->pending_response_prefix_len, ==, 0);
    munit_assert_size(session->last_picc_block_len, ==, 0);
    munit_assert_false(session->pending_response_staged);
}

static void assert_zeroed(const uint8_t* data, size_t length) {
    for(size_t i = 0; i < length; i++)
        munit_assert_uint8(data[i], ==, 0);
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
            Fixture baseline;
            open_record(&baseline, lengths[i]);
            uint8_t first_block[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
            size_t first_block_len = 0;
            begin_response_capture(&baseline, cid, first_block, &first_block_len);
            assert_record_block(first_block, first_block_len, cid);
            munit_assert_true(baseline.session->pending_response_staged);

            uint8_t retransmit[] = {
                (uint8_t)(DFC_ISO_DEP_R_BLOCK | (first_block[0] & DFC_ISO_DEP_SEQUENCE_BIT) |
                          (cid ? DFC_ISO_DEP_CID : 0)),
                cid};
            uint8_t retransmitted[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
            size_t retransmitted_len = 0;
            munit_assert_int(
                dfc_virtual_picc_iso_dep_frame_exchange(
                    baseline.session,
                    retransmit,
                    cid ? 2 : 1,
                    retransmitted,
                    sizeof(retransmitted),
                    &retransmitted_len),
                ==,
                DfcVirtualPiccStatusOk);
            munit_assert_size(retransmitted_len, ==, first_block_len);
            munit_assert_memory_equal(first_block_len, retransmitted, first_block);
            dfc_virtual_picc_session_free(baseline.session);

            for(size_t ack = 0; ack < sizeof(acknowledgements); ack++) {
                Fixture fixture;
                open_record(&fixture, lengths[i]);
                begin_response(&fixture, cid);
                size_t prefix = cid ? 2 : 1;
                munit_assert_true(fixture.session->pending_response_staged);

                // The emulator reset invalidates a lent buffer, including small replies.
                dfc_emulator_reset_session(fixture.session->emulator);
                reject_frame(&fixture, acknowledgements[ack], cid);

                uint8_t recovered[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
                size_t response_len = 0;
                exchange_read_record_frame(
                    &fixture,
                    cid,
                    fixture.session->expected_pcd_sequence,
                    recovered,
                    &response_len);
                munit_assert_uint8(recovered[0] & DFC_ISO_DEP_MORE, ==, DFC_ISO_DEP_MORE);
                assert_record_block(recovered, response_len, cid);
                munit_assert_size(response_len, ==, first_block_len);
                munit_assert_memory_equal(
                    first_block_len - prefix, recovered + prefix, first_block + prefix);
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
        memset(
            fixture.session->emulator->pending_chain,
            RecordByte,
            sizeof(fixture.session->emulator->pending_chain));
        switch(invalid) {
        case InvalidOffset:
            fixture.session->pending_response_offset = fixture.session->pending_response_len + 1;
            break;
        case InvalidOversizedLength:
            fixture.session->pending_response_len = SIZE_MAX;
            fixture.session->emulator->pending_chain_len = SIZE_MAX;
            break;
        case InvalidShortChainLength:
            fixture.session->emulator->pending_chain_len = 1;
            break;
        case InvalidResponseLengthMismatch:
            fixture.session->pending_response_len--;
            break;
        case InvalidOwnership:
            fixture.session->emulator->pending_chain_frame = 0;
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
        if(invalid == InvalidOversizedLength || invalid == InvalidShortChainLength ||
           invalid == InvalidResponseLengthMismatch || invalid == InvalidOwnership)
            assert_zeroed(
                fixture.session->emulator->pending_chain,
                sizeof(fixture.session->emulator->pending_chain));
        dfc_virtual_picc_session_free(fixture.session);
    }
    return MUNIT_OK;
}

static MunitResult
    test_normal_completion_wipes_exact_length(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    open_record(&fixture, HalfFileCapacity);
    begin_response(&fixture, 0);
    size_t staged_len = fixture.session->emulator->pending_chain_len;
    munit_assert_size(staged_len, <, sizeof(fixture.session->emulator->pending_chain));
    fixture.session->emulator->pending_chain[staged_len] = UntouchedOutputByte;
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t response_len = 0;
    while(fixture.session->pending_response_len > 0) {
        uint8_t ack = (uint8_t)(DFC_ISO_DEP_R_BLOCK | fixture.session->picc_sequence);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                fixture.session, &ack, sizeof(ack), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
    }
    assert_zeroed(fixture.session->emulator->pending_chain, staged_len);
    munit_assert_uint8(
        fixture.session->emulator->pending_chain[staged_len], ==, UntouchedOutputByte);
    dfc_virtual_picc_session_free(fixture.session);
    return MUNIT_OK;
}

static MunitResult
    test_timer_invalidation_retransmission_and_recovery(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    Fixture fixture;
    open_record(&fixture, HalfFileCapacity);
    DfcApplication* app = dfc_credential_get_application(&fixture.credential, 0);
    munit_assert_not_null(app);
    app->has_capability_data = true;
    app->capability_data[DFC_TRANSACTION_TIMER_CAPABILITY_OFFSET] = DFC_TRANSACTION_TIMER_SHORT;
    dfc_emulator_select_application(
        fixture.session->emulator, DfcEmulatorSelectedApplicationApp, 0);
    begin_response(&fixture, 0);
    munit_assert_true(fixture.session->emulator->transaction_timer_enabled);

    munit_assert_int(
        dfc_virtual_picc_advance_time(fixture.session, DFC_TRANSACTION_TIMER_EXPIRY_MILLISECONDS),
        ==,
        DfcVirtualPiccStatusOk);
    assert_retired(fixture.session);
    assert_zeroed(
        fixture.session->emulator->pending_chain,
        sizeof(fixture.session->emulator->pending_chain));

    const uint8_t retransmit = DFC_ISO_DEP_R_BLOCK | DFC_ISO_DEP_SEQUENCE_BIT;
    uint8_t response[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    memset(response, UntouchedOutputByte, sizeof(response));
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture.session,
            &retransmit,
            sizeof(retransmit),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusNoCard);
    munit_assert_size(response_len, ==, 0);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture.session, &activation), ==, DfcVirtualPiccStatusOk);
    const uint8_t version[] = {DFC_CMD_GET_VERSION};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture.session, version, sizeof(version), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >, 1);
    dfc_virtual_picc_session_free(fixture.session);
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
    {"/normal-completion-exact-wipe",
     test_normal_completion_wipes_exact_length,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/timer-invalidation-retransmission-recovery",
     test_timer_invalidation_retransmission_and_recovery,
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
