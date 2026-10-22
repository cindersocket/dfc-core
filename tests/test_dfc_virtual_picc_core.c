#include <stdio.h>
#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_port_host.h"
#include "dfc_emulator_i.h"

typedef struct {
    const void* target;
    size_t length;
    bool observed;
    bool zeroed;
} VirtualPiccFreeAudit;

static void observe_virtual_picc_free(const void* pointer, void* context) {
    VirtualPiccFreeAudit* audit = context;
    if(pointer != audit->target) return;
    audit->observed = true;
    audit->zeroed = true;
    const uint8_t* bytes = pointer;
    for(size_t i = 0; i < audit->length; i++) {
        if(bytes[i] != 0) audit->zeroed = false;
    }
}

static void activate_iso_dep(
    DfcVirtualPiccSession* session,
    uint8_t cid,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    const uint8_t rats[] = {0xE0, (uint8_t)(0x80 | cid)};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, response_capacity, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static MunitResult
    test_scan_and_iso_wrapped_exchange(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    munit_assert_size(activation.uid_len, ==, 7);
    munit_assert_uint8(activation.uid[0], ==, 0x04);
    munit_assert_uint8(activation.sak, ==, 0x20);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_picc_df[] = {
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            select_picc_df,
            sizeof(select_picc_df),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x90);
    munit_assert_uint8(response[1], ==, 0x00);

    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, 0x00);

    const uint8_t get_file_settings[] = {0x90, 0xF5, 0x00, 0x00, 0x01, 0x0F, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_file_settings,
            sizeof(get_file_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 9);
    // The fixture holds logical rights 0x1230, which go on the wire low octet first.
    munit_assert_memory_equal(
        7, response, ((uint8_t[]){0x00, 0x01, 0x30, 0x12, 0x03, 0x00, 0x00}));
    munit_assert_uint8(response[7], ==, 0x91);
    munit_assert_uint8(response[8], ==, 0x00);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_framed_unknown_iso_select_preserves_prefix_and_returns_not_found(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    DfcByteBuf* tx_buffer = dfc_bytebuf_alloc(DFC_WORKER_MAX_BUFFER_SIZE);
    const uint8_t prefix[] = {0x0A, 0x00};
    dfc_bytebuf_append_bytes(tx_buffer, prefix, sizeof(prefix));

    const uint8_t unknown_select[] = {
        0x00,
        DFC_ISO7816_INS_SELECT,
        0x04,
        0x00,
        0x0A,
        0xA0,
        0x00,
        0x00,
        0x01,
        0x51,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00};
    bool app_selected = true;

    munit_assert_true(dfc_emulator_handle_iso7816_select(
        emulator, unknown_select, sizeof(unknown_select), tx_buffer, sizeof(prefix), &app_selected));
    munit_assert_false(app_selected);
    munit_assert_size(dfc_bytebuf_get_size_bytes(tx_buffer), ==, 4);
    munit_assert_memory_equal(
        4, dfc_bytebuf_get_data(tx_buffer), ((uint8_t[]){0x0A, 0x00, 0x6A, 0x82}));

    dfc_bytebuf_free(tx_buffer);
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_frame_exchange_wraps_apdu(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 5);
    munit_assert_memory_equal(5, response, ((uint8_t[]){0x05, 0x65, 0x81, 0x02, 0x80}));

    const uint8_t select_picc_df[] = {
        0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    uint8_t wrong_sequence[sizeof(select_picc_df)];
    memcpy(wrong_sequence, select_picc_df, sizeof(wrong_sequence));
    wrong_sequence[0] ^= 1;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            wrong_sequence,
            sizeof(wrong_sequence),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_uint8(session->picc_sequence, ==, 0);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            select_picc_df,
            sizeof(select_picc_df),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));

    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            select_picc_df,
            sizeof(select_picc_df),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
    munit_assert_uint8(session->picc_sequence, ==, 1);

    const uint8_t r_nak[] = {0xB2};
    memset(response, 0, sizeof(response));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, r_nak, sizeof(r_nak), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));

    const uint8_t wrong_number_r_nak[] = {0xB3};
    memset(response, 0, sizeof(response));
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            wrong_number_r_nak,
            sizeof(wrong_number_r_nak),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0xA2);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_dep_reader_chaining(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t first[] = {0x12, 0x00, 0xA4};
    const uint8_t middle[] = {0x13, 0x04, 0x00, 0x07, 0xD2, 0x76};
    const uint8_t last[] = {0x02, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, 0, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0xA2);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 2);
    uint8_t oversized[sizeof(session->pending_command)] = {0x13};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, oversized, sizeof(oversized), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    munit_assert_size(session->pending_command_len, ==, 2);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
    for(uint8_t pcb = 0xB2; pcb <= 0xB3; pcb++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, &pcb, 1, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(response_len, ==, 1);
        munit_assert_uint8(response[0], ==, 0xA2);
        munit_assert_size(session->pending_command_len, ==, 2);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
    }
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, middle, sizeof(middle), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, 0xA3);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, last, sizeof(last), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));
    munit_assert_size(session->pending_command_len, ==, 0);
    for(unsigned i = 0; i < 2; i++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, rats, sizeof(rats), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, sizeof(first), response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 2);
    }
    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_size(session->pending_command_len, ==, 0);
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, first, sizeof(first), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t second[] = {0x03, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, second, sizeof(second), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x03, 0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void prepare_iso_file_session(
    DfcCredential* credential,
    DfcVirtualPiccSession** session,
    uint8_t cid,
    uint8_t* response,
    size_t* response_len) {
    load_standard_credential(credential);
    credential->files[0].comm_settings = DFC_COMM_PLAIN;
    *session = dfc_virtual_picc_session_alloc(credential);
    munit_assert_not_null(*session);
    activate_iso_dep(*session, cid, response, 64, response_len);
    (*session)->iso_file_selected = true;
    (*session)->iso_file_index = 0;
}

static void fill_iso_auth_pending_scratch(DfcEmulator* emulator, uint8_t phase) {
    emulator->iso_auth_phase = phase;
    emulator->iso_auth_challenge_len = DFC_ISO7816_AUTH_CHALLENGE_2TDEA;
    emulator->iso_auth_key_no = 3;
    emulator->iso_auth_cipher = DFC_CMD_AUTHENTICATE_ISO;
    emulator->iso_auth_reference = DFC_ISO7816_AUTH_APP_REFERENCE | 3;
    emulator->iso_auth_key_len = 16;
    memset(emulator->iso_auth_card_first, 0x11, sizeof(emulator->iso_auth_card_first));
    memset(emulator->iso_auth_host_first, 0x22, sizeof(emulator->iso_auth_host_first));
    memset(emulator->iso_auth_external_iv, 0x33, sizeof(emulator->iso_auth_external_iv));
    memset(emulator->iso_auth_key, 0x44, sizeof(emulator->iso_auth_key));
}

static void assert_iso_auth_pending_scratch_cleared(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_MAX_KEY_LEN] = {0};
    munit_assert_uint8(emulator->iso_auth_phase, ==, 0);
    munit_assert_uint8(emulator->iso_auth_challenge_len, ==, 0);
    munit_assert_uint8(emulator->iso_auth_key_no, ==, 0);
    munit_assert_uint8(emulator->iso_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->iso_auth_reference, ==, 0);
    munit_assert_size(emulator->iso_auth_key_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->iso_auth_card_first), emulator->iso_auth_card_first, zero);
    munit_assert_memory_equal(
        sizeof(emulator->iso_auth_host_first), emulator->iso_auth_host_first, zero);
    munit_assert_memory_equal(
        sizeof(emulator->iso_auth_external_iv), emulator->iso_auth_external_iv, zero);
    munit_assert_memory_equal(sizeof(emulator->iso_auth_key), emulator->iso_auth_key, zero);
}

static MunitResult test_iso_auth_terminal_paths_clear_pending_scratch(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t response[64];
    size_t response_len = 0;

    const uint8_t invalid_external[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_EXTERNAL_AUTHENTICATE, 0, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 1);
    DfcEmulator before = *session->emulator;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_external,
            sizeof(invalid_external),
            response,
            1,
            &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_memory_equal(sizeof(before), session->emulator, &before);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_external,
            sizeof(invalid_external),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    const uint8_t unexpected[] = {DFC_ISO7816_CLA_STANDARD, 0xFE, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 1);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, unexpected, sizeof(unexpected), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    const uint8_t invalid_internal[] = {
        DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_INTERNAL_AUTHENTICATE, 0, 0, 0};
    fill_iso_auth_pending_scratch(session->emulator, 2);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_internal,
            sizeof(invalid_internal),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    assert_iso_auth_pending_scratch_cleared(session->emulator);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_iso_dep_capacity_is_atomic_for_mutation_and_randomness(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len = 0;

    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t* file_data = dfc_file_data(&credential, &credential.files[0]);
        munit_assert_not_null(file_data);
        uint8_t update[8] = {0x02, 0x00, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xA5};
        size_t update_len = 7;
        size_t required = 3;
        if(cid != 0) {
            memmove(update + 2, update + 1, update_len - 1);
            update[0] = 0x0A;
            update[1] = cid;
            update_len++;
            required++;
        }
        uint8_t original = file_data[0];
        uint8_t expected_sequence = session->expected_pcd_sequence;
        uint8_t picc_sequence = session->picc_sequence;
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, update, update_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(response_len, ==, 0);
        munit_assert_uint8(file_data[0], ==, original);
        munit_assert_uint8(session->expected_pcd_sequence, ==, expected_sequence);
        munit_assert_uint8(session->picc_sequence, ==, picc_sequence);
        munit_assert_size(session->pending_response_len, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, update, update_len, response, required, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(file_data[0], ==, 0xA5);
        munit_assert_size(response_len, ==, required);
        dfc_virtual_picc_session_free(session);
    }

    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t random_script[DFC_ISO7816_AUTH_CHALLENGE_2TDEA];
        memset(random_script, 0x5A, sizeof(random_script));
        dfc_host_clear_random_buffer();
        dfc_host_set_random_buffer(random_script, sizeof(random_script));
        uint8_t challenge[7] = {
            0x02,
            DFC_ISO7816_CLA_STANDARD,
            DFC_ISO7816_INS_GET_CHALLENGE,
            0,
            0,
            DFC_ISO7816_AUTH_CHALLENGE_2TDEA};
        size_t challenge_len = 6;
        size_t required = 1 + sizeof(random_script) + DFC_ISO7816_STATUS_WORD_LENGTH;
        if(cid != 0) {
            memmove(challenge + 2, challenge + 1, challenge_len - 1);
            challenge[0] = 0x0A;
            challenge[1] = cid;
            challenge_len++;
            required++;
        }
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, challenge, challenge_len, response, required - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(dfc_host_random_remaining(), ==, sizeof(random_script));
        munit_assert_uint8(session->emulator->iso_auth_phase, ==, 0);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, challenge, challenge_len, response, required, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(dfc_host_random_remaining(), ==, 0);
        munit_assert_size(response_len, ==, required);
        dfc_host_clear_random_buffer();
        dfc_virtual_picc_session_free(session);
    }

    return MUNIT_OK;
}

static MunitResult test_iso_dep_capacity_is_atomic_for_chained_commands(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t response[64];
    size_t response_len = 0;
    for(uint8_t cid = 0; cid <= 3; cid += 3) {
        DfcCredential credential;
        DfcVirtualPiccSession* session = NULL;
        prepare_iso_file_session(&credential, &session, cid, response, &response_len);
        uint8_t* file_data = dfc_file_data(&credential, &credential.files[0]);
        uint8_t first[5] = {0x12, DFC_ISO7816_CLA_STANDARD, DFC_ISO7816_INS_UPDATE_BINARY, 0};
        size_t first_len = 4;
        size_t r_block_len = 1;
        if(cid != 0) {
            memmove(first + 2, first + 1, first_len - 1);
            first[0] = 0x1A;
            first[1] = cid;
            first_len++;
            r_block_len++;
        }
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, first_len, response, r_block_len - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_size(session->pending_command_len, ==, 0);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, first, first_len, response, r_block_len, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_size(session->pending_command_len, ==, 3);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);

        uint8_t final[5] = {0x03, 0, 1, 0xA6};
        size_t final_len = 4;
        size_t response_block_len = 3;
        if(cid != 0) {
            memmove(final + 2, final + 1, final_len - 1);
            final[0] = 0x0B;
            final[1] = cid;
            final_len++;
            response_block_len++;
        }
        uint8_t original = file_data[0];
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, final, final_len, response, response_block_len - 1, &response_len),
            ==,
            DfcVirtualPiccStatusBufferTooSmall);
        munit_assert_uint8(file_data[0], ==, original);
        munit_assert_size(session->pending_command_len, ==, 3);
        munit_assert_uint8(session->expected_pcd_sequence, ==, 1);
        munit_assert_int(
            dfc_virtual_picc_iso_dep_frame_exchange(
                session, final, final_len, response, response_block_len, &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_uint8(file_data[0], ==, 0xA6);
        munit_assert_size(session->pending_command_len, ==, 0);
        dfc_virtual_picc_session_free(session);
    }
    return MUNIT_OK;
}

static MunitResult test_iso_file_capacity_and_request_classification(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcFile* file = &credential.files[0];
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->record_size = 3;
    file->record_count = 1;
    file->comm_settings = DFC_COMM_PLAIN;
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->iso_file_selected = true;
    session->iso_file_index = 0;
    uint8_t response[8];
    size_t response_len = 0;
    const uint8_t read_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 1, 0, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_record, sizeof(read_record), response, 4, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_size(response_len, ==, 0);
    const uint8_t invalid_record[] = {0, DFC_ISO7816_INS_READ_RECORD, 2, 0, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            invalid_record,
            sizeof(invalid_record),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x6A, 0x86}));

    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    const uint8_t read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, read_binary, sizeof(read_binary), response, 4, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    uint8_t* data = dfc_file_data(&credential, file);
    uint8_t original = data[0];
    const uint8_t update_binary[] = {0, DFC_ISO7816_INS_UPDATE_BINARY, 0, 0, 1, 0xCC};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, update_binary, sizeof(update_binary), response, 1, &response_len),
        ==,
        DfcVirtualPiccStatusBufferTooSmall);
    munit_assert_uint8(data[0], ==, original);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_wrapped_oversize_is_terminal(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    uint8_t oversized[DFC_WORKER_MAX_BUFFER_SIZE + 7] = {0};
    oversized[0] = DFC_ISO7816_CLA_WRAPPER;
    oversized[1] = DFC_CMD_GET_VERSION;
    uint8_t response[2];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, oversized, sizeof(oversized), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_LENGTH_ERROR}));
    munit_assert_size(session->pending_response_len, ==, 0);
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_virtual_picc_reset_and_free_wipe_transport_storage(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    memset(session->pending_command, 0xA1, sizeof(session->pending_command));
    memset(session->pending_response, 0xA2, sizeof(session->pending_response));
    memset(session->pending_response_prefix, 0xA3, sizeof(session->pending_response_prefix));
    memset(session->last_picc_block, 0xA4, sizeof(session->last_picc_block));
    session->pending_command_len = 7;
    session->pending_response_len = 8;
    session->pending_response_offset = 2;
    session->pending_response_prefix_len = 2;
    session->last_picc_block_len = 4;
    munit_assert_int(dfc_virtual_picc_reset_protocol(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(
        sizeof(session->pending_command),
        session->pending_command,
        ((uint8_t[sizeof(session->pending_command)]){0}));
    munit_assert_memory_equal(
        sizeof(session->pending_response),
        session->pending_response,
        ((uint8_t[sizeof(session->pending_response)]){0}));
    munit_assert_memory_equal(
        sizeof(session->pending_response_prefix),
        session->pending_response_prefix,
        ((uint8_t[sizeof(session->pending_response_prefix)]){0}));
    munit_assert_memory_equal(
        sizeof(session->last_picc_block),
        session->last_picc_block,
        ((uint8_t[sizeof(session->last_picc_block)]){0}));

    memset(session->pending_command, 0xB1, sizeof(session->pending_command));
    memset(session->pending_response, 0xB2, sizeof(session->pending_response));
    memset(session->last_picc_block, 0xB3, sizeof(session->last_picc_block));
    VirtualPiccFreeAudit audit = {
        .target = session,
        .length = sizeof(*session),
    };
    dfc_host_set_free_observer(observe_virtual_picc_free, &audit);
    dfc_virtual_picc_session_free(session);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.observed);
    munit_assert_true(audit.zeroed);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_response_chain_followup(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    // Seed the transport after sending the first 50 bytes of a chained response.
    session->iso_dep_selected = true;
    session->expected_pcd_sequence = 1;
    session->picc_sequence = 1;
    session->pending_response_len = 60;
    session->pending_response_offset = 50;
    session->last_picc_block_len = 51;
    session->last_picc_block[0] = 0x12;
    for(unsigned i = 0; i < 60; i++)
        session->pending_response[i] = (uint8_t)i;
    memcpy(session->last_picc_block + 1, session->pending_response, 50);
    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t retry[] = {0xA2};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, retry, sizeof(retry), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 51);
    munit_assert_memory_equal(51, response, session->last_picc_block);
    munit_assert_size(session->pending_response_offset, ==, 50);
    const uint8_t ack[] = {0xA3};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, ack, sizeof(ack), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 11);
    munit_assert_uint8(response[0], ==, 0x03);
    munit_assert_memory_equal(10, response + 1, session->pending_response + 50);
    const uint8_t select[] = {0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0, 0, 0x85, 1, 0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, select, sizeof(select), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 3);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));
    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_cid_response_sets_chaining_bit(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);
    session->iso_dep_selected = true;
    session->picc_sequence = 0;
    session->pending_response_len = 58;
    session->pending_response_offset = 0;
    session->pending_response_prefix[0] = 0x0A;
    session->pending_response_prefix[1] = 0x00;
    session->pending_response_prefix_len = 2;
    session->last_picc_block[0] = 0x03;
    session->last_picc_block_len = 1;
    for(size_t i = 0; i < session->pending_response_len; i++)
        session->pending_response[i] = (uint8_t)i;

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t ack[] = {0xA0};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, ack, sizeof(ack), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 50);
    munit_assert_uint8(response[0], ==, 0x1A);
    munit_assert_uint8(response[1], ==, 0x00);
    munit_assert_memory_equal(48, response + 2, session->pending_response);

    const uint8_t next[] = {0xA9, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, next, sizeof(next), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 12);
    munit_assert_uint8(response[0], ==, 0x0B);
    munit_assert_uint8(response[1], ==, 0x00);
    munit_assert_memory_equal(10, response + 2, session->pending_response + 48);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_rejects_unadvertised_nad(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[16];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    const uint8_t nad_frame[] = {0x06, 0x01, 0x90, 0x45, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, nad_frame, sizeof(nad_frame), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_iso_dep_enforces_and_echoes_cid(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[16];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x83};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(session->iso_dep_cid, ==, 3);

    const uint8_t missing_cid[] = {0x02, 0x90};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, missing_cid, sizeof(missing_cid), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    const uint8_t wrong_cid[] = {0x0A, 0x02, 0x90};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, wrong_cid, sizeof(wrong_cid), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);

    const uint8_t chained[] = {0x1A, 0x03, 0x90};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, chained, sizeof(chained), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0xAA, 0x03}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void assert_repeated_reader_frame_cycle(DfcVirtualPiccSession* session) {
    // This fixture exercises ISO-DEP framing, not access-control policy.
    session->credential->files[0].access_rights = 0xEEEE;

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t rats[] = {0xE0, 0x80};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t select_picc_df[] = {
        0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            select_picc_df,
            sizeof(select_picc_df),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x02, 0x90, 0x00}));

    const uint8_t select_app[] = {0x03, 0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(3, response, ((uint8_t[]){0x03, 0x91, 0x00}));

    const uint8_t get_file_settings[] = {0x02, 0x90, 0xF5, 0x00, 0x00, 0x01, 0x0F, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            get_file_settings,
            sizeof(get_file_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 10);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x02, 0x00}));

    // Length 0 = entire file (3 bytes on the standard fixture).
    const uint8_t read_file[] = {
        0x03, 0x90, 0xBD, 0x00, 0x00, 0x07, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session, read_file, sizeof(read_file), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, >, 2);
    munit_assert_uint8(response[0], ==, 0x03);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, 0x00);

    const uint8_t select_picc_native[] = {
        0x02, 0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            select_picc_native,
            sizeof(select_picc_native),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    const uint8_t deselect_with_cid[] = {0xCA, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            session,
            deselect_with_cid,
            sizeof(deselect_with_cid),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(2, response, deselect_with_cid);

    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
}

static MunitResult test_reader_frame_cycle_repeats_after_field_off(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    credential.files[0].access_rights = 0xEEEE;
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    assert_repeated_reader_frame_cycle(session);
    assert_repeated_reader_frame_cycle(session);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_protocol_and_field_resets_reuse_allocations(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(session);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    DfcEmulator* emulator = session->emulator;
    DfcByteBuf* tx_buffer = emulator->tx_buffer;
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 1;
    emulator->awaiting_step2 = true;
    session->iso_dep_selected = true;
    session->expected_pcd_sequence = 1;

    munit_assert_int(dfc_virtual_picc_reset_protocol(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_ptr_equal(session->emulator, emulator);
    munit_assert_ptr_equal(session->emulator->tx_buffer, tx_buffer);
    munit_assert_true(session->activated);
    munit_assert_false(session->iso_dep_selected);
    munit_assert_uint8(session->expected_pcd_sequence, ==, 0);
    munit_assert_int(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);
    munit_assert_false(session->emulator->awaiting_step2);

    munit_assert_int(dfc_virtual_picc_field_off(session), ==, DfcVirtualPiccStatusOk);
    munit_assert_ptr_equal(session->emulator, emulator);
    munit_assert_ptr_equal(session->emulator->tx_buffer, tx_buffer);
    munit_assert_false(session->activated);
    munit_assert_false(session->random_uid_valid);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult test_scan_reports_on_device_desfire_activation_vector(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    munit_assert_size(activation.protocol_len, ==, 2);
    munit_assert_memory_equal(2, activation.protocol, ((uint8_t[]){0x02, 0x02}));
    munit_assert_size(activation.uid_len, ==, 7);
    munit_assert_uint8(activation.uid[0], ==, 0x04);
    munit_assert_size(activation.ats_len, ==, 5);
    munit_assert_memory_equal(5, activation.ats, ((uint8_t[]){0x05, 0x65, 0x81, 0x02, 0x80}));
    munit_assert_uint8(activation.sak, ==, 0x20);
    munit_assert_size(activation.atqa_len, ==, 2);
    munit_assert_memory_equal(2, activation.atqa, ((uint8_t[]){0x44, 0x03}));
    munit_assert_size(activation.rf_detail_len, ==, 3);
    munit_assert_memory_equal(3, activation.rf_detail, ((uint8_t[]){0x01, 0x51, 0x57}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_random_id_uses_single_size_atqa(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    credential.picc_random_id = true;

    DfcVirtualPiccActivation activation;
    dfc_virtual_picc_anticollision(&credential, &activation);
    munit_assert_size(activation.uid_len, ==, 4);
    munit_assert_memory_equal(2, activation.atqa, ((uint8_t[]){0x04, 0x03}));

    credential.picc_has_atqa = true;
    credential.picc_atqa[0] = 0x00;
    credential.picc_atqa[1] = 0x04;
    dfc_virtual_picc_anticollision(&credential, &activation);
    munit_assert_memory_equal(2, activation.atqa, credential.picc_atqa);
    return MUNIT_OK;
}

static MunitResult test_wrapped_get_version_returns_detection_frame(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t command[DFC_WRAPPED_GET_VERSION_FRAME_SIZE];
    dfc_build_wrapped_get_version_frame(command);

    uint8_t response[128];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, sizeof(command), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);

    uint8_t expected[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x16, 0x05, 0x91, 0xAF};
    munit_assert_size(response_len, ==, sizeof(expected));
    munit_assert_memory_equal(sizeof(expected), response, expected);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitResult
    test_unknown_native_aid_returns_to_picc_level(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_standard_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    uint8_t response[128];
    size_t response_len = 0;
    const uint8_t select_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, select_app, sizeof(select_app), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_uint8(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);

    const uint8_t select_missing_app[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0xEF, 0xBE, 0xAD, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            select_missing_app,
            sizeof(select_missing_app),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_APPLICATION_NOT_FOUND}));
    munit_assert_uint8(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationPicc);

    // No application is selected, so this is refused before any file access
    // rights are consulted and stays 0x9D.
    const uint8_t get_file_ids[] = {0x90, 0x6F, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, get_file_ids, sizeof(get_file_ids), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(2, response, ((uint8_t[]){0x91, DFC_STATUS_PERMISSION_DENIED}));

    const uint8_t get_key_settings[] = {0x90, 0x45, 0x00, 0x00, 0x00};
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session,
            get_key_settings,
            sizeof(get_key_settings),
            response,
            sizeof(response),
            &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_memory_equal(4, response, ((uint8_t[]){0x0F, 0x01, 0x91, 0x00}));

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static void load_factory_d40_credential(DfcCredential* credential) {
    dfc_credential_clear(credential);
    memcpy(
        credential->uid,
        ((uint8_t[]){0x04, 0x02, 0xA5, 0xDA, 0x4F, 0x85, 0x5C}),
        DFC_DESFIRE_UID_LEN);
    credential->uid_len = DFC_DESFIRE_UID_LEN;

    const uint8_t factory_aid_desfire_order[] = {0x4F, 0x49, 0x53};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        credential, factory_aid_desfire_order, 0x0B, DFC_KEY_TYPE_DES_2K3DES | 4);
    munit_assert_not_null(app);
    const uint8_t iso_aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};
    memcpy(app->iso_aid, iso_aid, sizeof(iso_aid));
    app->iso_aid_len = sizeof(iso_aid);
    app->auth_command = DFC_CMD_AUTHENTICATE_LEGACY;

    const uint8_t keys[][16] = {
        {0x5E,
         0xA0,
         0xA3,
         0xE3,
         0xA8,
         0xD2,
         0x20,
         0x6C,
         0xB3,
         0x96,
         0xC9,
         0xC8,
         0xDE,
         0xA9,
         0xC2,
         0xD9},
        {0xF9,
         0xF5,
         0xE5,
         0xBE,
         0x4D,
         0xEA,
         0x54,
         0xC6,
         0xB6,
         0xD2,
         0x5E,
         0x28,
         0xA8,
         0xBF,
         0xA1,
         0x56},
        {0x54,
         0x0A,
         0xF5,
         0x62,
         0x1B,
         0xD3,
         0x5C,
         0xB3,
         0x82,
         0x70,
         0xC2,
         0x50,
         0x06,
         0x3D,
         0x41,
         0x25},
        {0xC5,
         0x76,
         0x16,
         0x55,
         0x74,
         0xAC,
         0x9F,
         0x5E,
         0x84,
         0x5E,
         0x63,
         0xF3,
         0x3F,
         0x9F,
         0x4B,
         0x20},
    };
    for(size_t i = 0; i < 4; i++) {
        memcpy(dfc_credential_key(credential, app, i), keys[i], app->key_len);
    }

    DfcFile* file = dfc_credential_create_file(credential, 0, 0x0F);
    munit_assert_not_null(file);
    file->type = 0x00;
    file->comm_settings = DFC_COMM_MAC;
    // The captured card answers GetFileSettings with access-rights octets 12 03.
    // Those arrive least-significant octet first, so the logical value is 0x0312:
    // read key 0, write key 3, read&write key 1, change key 2.
    file->access_rights = 0x0312;
    static const uint8_t file_data[] = {0x30, 0x2F, 0x81, 0x02, 0x0C, 0x03, 0xA5, 0x02, 0x05,
                                        0x00, 0xA6, 0x08, 0x81, 0x01, 0x01, 0x04, 0x03, 0x03,
                                        0x00, 0x09, 0xA7, 0x17, 0x85, 0x15, 0xD2, 0x0B, 0x74,
                                        0x96, 0x7B, 0xE1, 0x16, 0x31, 0xE9, 0xC4, 0x02, 0x4B,
                                        0xD6, 0xDB, 0x18, 0xF5, 0x68, 0x2B, 0xE0, 0x7D, 0xA4,
                                        0xA9, 0x02, 0x05, 0x00, 0x05, 0x00};
    munit_assert_true(dfc_file_resize(credential, file, sizeof(file_data)));
    memcpy(dfc_file_data(credential, file), file_data, sizeof(file_data));
}

static void assert_trace_exchange(
    DfcVirtualPiccSession* session,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* expected,
    size_t expected_len) {
    uint8_t response[128];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            session, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    if(response_len != expected_len || memcmp(response, expected, expected_len) != 0) {
        printf("command=");
        for(size_t i = 0; i < command_len; i++)
            printf("%02X", command[i]);
        printf("\nexpected=");
        for(size_t i = 0; i < expected_len; i++)
            printf("%02X", expected[i]);
        printf("\nactual=");
        for(size_t i = 0; i < response_len; i++)
            printf("%02X", response[i]);
        printf("\n");
    }
    munit_assert_size(response_len, ==, expected_len);
    munit_assert_memory_equal(expected_len, response, expected);
}

static MunitResult
    test_factory_d40_trace_select_auth_read_path(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    DfcCredential credential;
    load_factory_d40_credential(&credential);
    DfcVirtualPiccSession* session = dfc_virtual_picc_session_alloc(&credential);

    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(session, &activation), ==, DfcVirtualPiccStatusOk);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00}),
        12,
        ((uint8_t[]){0x90, 0x00}),
        2);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x4F, 0x49, 0xD3, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_APPLICATION_NOT_FOUND}),
        2);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x4F, 0x49, 0x53, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_OK}),
        2);
    munit_assert_uint8(
        session->emulator->selected_application, ==, DfcEmulatorSelectedApplicationApp);

    const uint8_t captured_rnd_b[] = {0x5E, 0xE1, 0x1A, 0x07, 0x43, 0xFB, 0x4E, 0xB5};
    dfc_host_set_random_buffer(captured_rnd_b, sizeof(captured_rnd_b));
    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_AUTHENTICATE_LEGACY, 0x00, 0x00, 0x01, 0x01, 0x00}),
        7,
        ((uint8_t[]){
            0x61, 0xBA, 0x91, 0xCD, 0x03, 0x13, 0x98, 0xD5, 0x91, DFC_CMD_ADDITIONAL_FRAME}),
        10);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_ADDITIONAL_FRAME,
                     0x00, 0x00,
                     0x10, 0xD3,
                     0x59, 0x19,
                     0x7F, 0x16,
                     0xEF, 0x09,
                     0xE4, 0xBE,
                     0x33, 0x3E,
                     0x63, 0xCC,
                     0xF2, 0xC1,
                     0x1B, 0x00}),
        22,
        ((uint8_t[]){0xA4, 0x4A, 0x65, 0xA8, 0x62, 0xF4, 0xA9, 0x54, 0x91, DFC_STATUS_OK}),
        10);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, 0x0F, 0x00}),
        7,
        ((uint8_t[]){0x00, 0x01, 0x12, 0x03, 0x33, 0x00, 0x00, 0x91, DFC_STATUS_OK}),
        9);

    assert_trace_exchange(
        session,
        ((uint8_t[]){
            0x90,
            DFC_CMD_READ_DATA,
            0x00,
            0x00,
            0x07,
            0x0F,
            0x00,
            0x00,
            0x00,
            0x05,
            0x00,
            0x00,
            0x00}),
        13,
        ((uint8_t[]){0x30, 0x2F, 0x81, 0x02, 0x0C, 0x1E, 0xA1, 0x78, 0x17, 0x91, DFC_STATUS_OK}),
        11);

    assert_trace_exchange(
        session,
        ((uint8_t[]){
            0x90,
            DFC_CMD_READ_DATA,
            0x00,
            0x00,
            0x07,
            0x0F,
            0x00,
            0x00,
            0x00,
            0x31,
            0x00,
            0x00,
            0x00}),
        13,
        ((uint8_t[]){0x30, 0x2F, 0x81, 0x02, 0x0C, 0x03, 0xA5, 0x02, 0x05, 0x00, 0xA6,
                     0x08, 0x81, 0x01, 0x01, 0x04, 0x03, 0x03, 0x00, 0x09, 0xA7, 0x17,
                     0x85, 0x15, 0xD2, 0x0B, 0x74, 0x96, 0x7B, 0xE1, 0x16, 0x31, 0xE9,
                     0xC4, 0x02, 0x4B, 0xD6, 0xDB, 0x18, 0xF5, 0x68, 0x2B, 0xE0, 0x7D,
                     0xA4, 0xA9, 0x02, 0x05, 0x00, 0xEF, 0x5C, 0x8D, 0x4A, 0x91, DFC_STATUS_OK}),
        55);

    assert_trace_exchange(
        session,
        ((uint8_t[]){0x90, DFC_CMD_SELECT_APPLICATION, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}),
        9,
        ((uint8_t[]){0x91, DFC_STATUS_OK}),
        2);

    dfc_virtual_picc_session_free(session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/iso-auth-terminal-scratch-wipe",
     test_iso_auth_terminal_paths_clear_pending_scratch,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-capacity-atomic-mutation-random",
     test_iso_dep_capacity_is_atomic_for_mutation_and_randomness,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-capacity-atomic-chained-command",
     test_iso_dep_capacity_is_atomic_for_chained_commands,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-file-capacity-and-request-classification",
     test_iso_file_capacity_and_request_classification,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-wrapped-oversize-is-terminal",
     test_iso_wrapped_oversize_is_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reset-and-free-wipe-transport-storage",
     test_virtual_picc_reset_and_free_wipe_transport_storage,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-enforces-and-echoes-cid",
     test_iso_dep_enforces_and_echoes_cid,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-rejects-unadvertised-nad",
     test_iso_dep_rejects_unadvertised_nad,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-cid-response-sets-chaining-bit",
     test_iso_dep_cid_response_sets_chaining_bit,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-response-chain-followup",
     test_iso_dep_response_chain_followup,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-reader-chaining",
     test_iso_dep_reader_chaining,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/scan-and-iso-wrapped-exchange",
     test_scan_and_iso_wrapped_exchange,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/framed-unknown-iso-select-preserves-prefix-and-returns-not-found",
     test_framed_unknown_iso_select_preserves_prefix_and_returns_not_found,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/iso-dep-frame-exchange-wraps-apdu",
     test_iso_dep_frame_exchange_wraps_apdu,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader-frame-cycle-repeats-after-field-off",
     test_reader_frame_cycle_repeats_after_field_off,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/protocol-and-field-resets-reuse-allocations",
     test_protocol_and_field_resets_reuse_allocations,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/scan-reports-on-device-desfire-activation-vector",
     test_scan_reports_on_device_desfire_activation_vector,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/random-id-uses-single-size-atqa",
     test_random_id_uses_single_size_atqa,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/wrapped-get-version-detection-frame",
     test_wrapped_get_version_returns_detection_frame,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/unknown-native-aid-returns-to-picc-level",
     test_unknown_native_aid_returns_to_picc_level,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/factory-d40-trace-select-auth-read-path",
     test_factory_d40_trace_select_auth_read_path,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_virtual_picc_core", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
