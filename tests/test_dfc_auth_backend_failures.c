#include "munit.h"

#include "auth_fault_test_support.h"

#include <string.h>

static void build_start_apdu(const AuthCase* auth_case, uint8_t apdu[8], size_t* apdu_len) {
    memset(apdu, 0, 8);
    apdu[0] = 0x90;
    apdu[1] = auth_case->command;
    apdu[4] = auth_case->ev2 && !auth_case->non_first ? 2 : 1;
    apdu[5] = 0;
    if(apdu[4] == 2) apdu[6] = 0;
    *apdu_len = 6 + apdu[4];
}

static void exchange(
    AuthFixture* fixture,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t response[64],
    size_t* response_len) {
    memset(response, 0xA5, 64);
    *response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            fixture->session, apdu, apdu_len, response, 64, response_len),
        ==,
        DfcVirtualPiccStatusOk);
}

static void exchange_native(
    AuthFixture* fixture,
    const uint8_t* command,
    size_t command_len,
    uint8_t response[64],
    size_t* response_len) {
    DfcByteBuf* tx = dfc_bytebuf_alloc(64);
    munit_assert_not_null(tx);
    munit_assert_true(
        dfc_emulator_handle_command(fixture->session->emulator, command, command_len, tx, NULL));
    *response_len = dfc_bytebuf_get_size_bytes(tx);
    memcpy(response, dfc_bytebuf_get_data(tx), *response_len);
    dfc_bytebuf_free(tx);
}

static void assert_status(const uint8_t* response, size_t response_len, uint8_t status) {
    munit_assert_size(response_len, ==, 2);
    munit_assert_uint8(response[0], ==, 0x91);
    munit_assert_uint8(response[1], ==, status);
}

static void assert_pending_cleared(const DfcEmulator* emulator) {
    static const uint8_t zero[DFC_EV2_RANDOM_LENGTH] = {0};
    munit_assert_false(emulator->awaiting_step2);
    munit_assert_uint8(emulator->pending_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->pending_auth_key_no, ==, 0);
    munit_assert_memory_equal(sizeof(emulator->rnd_b), emulator->rnd_b, zero);
    munit_assert_memory_equal(sizeof(emulator->enc_rnd_b), emulator->enc_rnd_b, zero);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    munit_assert_false(emulator->ev2_authentication_pending);
    munit_assert_false(emulator->ev2_authentication_non_first);
    munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
    munit_assert_memory_equal(sizeof(emulator->ev2_static_key), emulator->ev2_static_key, zero);
    munit_assert_memory_equal(sizeof(emulator->ev2_random_b), emulator->ev2_random_b, zero);
#endif
}

static void assert_transaction_outcome(const AuthCase* auth_case, const AuthFixture* fixture) {
    bool preserve = auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY;
    munit_assert_int(fixture->value_file->state.value.pending, ==, preserve);
    munit_assert_int32(fixture->value_file->state.value.pending_delta, ==, preserve ? 2 : 0);
    munit_assert_int32(fixture->value_file->state.value.current, ==, 40);
}

static void assert_fixture_prior_session(const AuthCase* auth_case, const DfcEmulator* emulator) {
    if(auth_case->ev2 && auth_case->non_first) {
        uint8_t encryption_key[DFC_AES_KEY_LENGTH];
        uint8_t mac_key[DFC_AES_KEY_LENGTH];
        uint8_t transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH];
        memset(encryption_key, 0x42, sizeof(encryption_key));
        memset(mac_key, 0x43, sizeof(mac_key));
        memset(transaction_identifier, 0x44, sizeof(transaction_identifier));
        munit_assert_true(emulator->ev2_session_active);
        munit_assert_memory_equal(
            sizeof(encryption_key), emulator->ev2_session_encryption_key, encryption_key);
        munit_assert_memory_equal(sizeof(mac_key), emulator->ev2_session_mac_key, mac_key);
        munit_assert_memory_equal(
            sizeof(transaction_identifier),
            emulator->ev2_transaction_identifier,
            transaction_identifier);
        return;
    }

    munit_assert_true(dfc_emulator_native_authentication_active(emulator));
    uint8_t expected_cipher = auth_case->ev2 ? DFC_CMD_AUTHENTICATE_AES : auth_case->command;
    munit_assert_uint8(emulator->secure_messaging->cipher, ==, expected_cipher);
    size_t expected_key_len = auth_case->command == DFC_CMD_AUTHENTICATE_ISO ? 24 : 16;
    munit_assert_size(emulator->secure_messaging->session_key_len, ==, expected_key_len);
    for(size_t i = 0; i < expected_key_len; i++)
        munit_assert_uint8(emulator->secure_messaging->session_key[i], ==, 0x52);
    for(size_t i = 0; i < sizeof(emulator->secure_messaging->iv); i++)
        munit_assert_uint8(emulator->secure_messaging->iv[i], ==, 0x55);
}

static void assert_authentication_retired(const DfcEmulator* emulator);

static MunitResult
    test_start_failures_report_memory_error(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t case_index = 0; case_index < auth_case_count; case_index++) {
        {
            for(size_t framing = 0; framing < 2; framing++) {
                auth_faults_clear();
                AuthFixture fixture;
                const AuthCase* auth_case = &auth_cases[case_index];
                auth_fixture_open(&fixture, auth_case);
                DfcEmulator* emulator = fixture.session->emulator;
                assert_fixture_prior_session(auth_case, emulator);

                if(auth_case->command == DFC_CMD_AUTHENTICATE_AES || auth_case->ev2) {
                    fail_aes_cbc_call = 1;
                } else {
                    fail_des_cbc_call = 1;
                }

                uint8_t response[64];
                size_t response_len = 0;
                if(framing == 0) {
                    uint8_t native[] = {auth_case->command, 0, 0};
                    size_t native_len = auth_case->ev2 && !auth_case->non_first ? 3 : 2;
                    exchange_native(&fixture, native, native_len, response, &response_len);
                    munit_assert_size(response_len, ==, 1);
                    munit_assert_uint8(response[0], ==, DFC_STATUS_MEMORY_ERROR);
                } else {
                    uint8_t apdu[8];
                    size_t apdu_len = 0;
                    build_start_apdu(auth_case, apdu, &apdu_len);
                    exchange(&fixture, apdu, apdu_len, response, &response_len);
                    assert_status(response, response_len, DFC_STATUS_MEMORY_ERROR);
                }
                assert_authentication_retired(emulator);
                assert_pending_cleared(emulator);
                assert_transaction_outcome(auth_case, &fixture);
                auth_fixture_close(&fixture);
            }
        }
    }
    auth_faults_clear();
    return MUNIT_OK;
}

static MunitResult test_random_generation_failures_report_memory_error(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t case_index = 0; case_index < auth_case_count; case_index++) {
        for(size_t framing = 0; framing < 2; framing++) {
            auth_faults_clear();
            AuthFixture fixture;
            const AuthCase* auth_case = &auth_cases[case_index];
            auth_fixture_open(&fixture, auth_case);
            assert_fixture_prior_session(auth_case, fixture.session->emulator);

            uint8_t response[64] = {0};
            size_t response_len = 0;
            fail_random = true;
            if(framing == 0) {
                uint8_t native[] = {auth_case->command, 0, 0};
                size_t native_len = auth_case->ev2 && !auth_case->non_first ? 3 : 2;
                exchange_native(&fixture, native, native_len, response, &response_len);
                munit_assert_size(response_len, ==, 1);
                munit_assert_uint8(response[0], ==, DFC_STATUS_MEMORY_ERROR);
            } else {
                uint8_t apdu[8];
                size_t apdu_len = 0;
                build_start_apdu(auth_case, apdu, &apdu_len);
                exchange(&fixture, apdu, apdu_len, response, &response_len);
                assert_status(response, response_len, DFC_STATUS_MEMORY_ERROR);
            }
            assert_authentication_retired(fixture.session->emulator);
            assert_pending_cleared(fixture.session->emulator);
            assert_transaction_outcome(auth_case, &fixture);
            auth_fixture_close(&fixture);
        }
    }
    auth_faults_clear();
    return MUNIT_OK;
}

static size_t challenge_length(const AuthCase* auth_case) {
    return auth_case->command == DFC_CMD_AUTHENTICATE_AES ||
                   auth_case->command == DFC_CMD_AUTHENTICATE_ISO || auth_case->ev2 ?
               16 :
               8;
}

static void build_continuation_apdu(
    const AuthCase* auth_case,
    const DfcEmulator* emulator,
    bool valid,
    uint8_t apdu[38],
    size_t* apdu_len) {
    size_t random_len = challenge_length(auth_case);
    size_t clear_len = auth_case->ev2 ? DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH : random_len * 2;
    uint8_t clear[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH] = {0};
    for(size_t i = 0; i < random_len; i++)
        clear[i] = (uint8_t)(0x70 + i);
    const uint8_t* random_b = auth_case->ev2 ? emulator->ev2_random_b : emulator->rnd_b;
    for(size_t i = 0; i < random_len; i++)
        clear[random_len + i] = random_b[(i + 1) % random_len];
    if(!valid) clear[clear_len - 1] ^= 0x80;

    memset(apdu, 0, 38);
    apdu[0] = 0x90;
    apdu[1] = DFC_CMD_ADDITIONAL_FRAME;
    apdu[4] = (uint8_t)clear_len;
    if(auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY) {
        for(size_t i = 0; i < 8; i++)
            apdu[5 + i] = clear[i] ^ 0x52;
        for(size_t i = 0; i < 8; i++)
            apdu[13 + i] = clear[8 + i] ^ 0x53 ^ apdu[5 + i];
    } else {
        for(size_t i = 0; i < clear_len; i++)
            apdu[5 + i] = clear[i] ^ 0xA7;
    }
    apdu[5 + clear_len] = 0;
    *apdu_len = 6 + clear_len;
    dfc_secure_wipe(clear, sizeof(clear));
}

static void begin_authentication(
    AuthFixture* fixture,
    const AuthCase* auth_case,
    uint8_t continuation[38],
    size_t* continuation_len,
    bool valid) {
    uint8_t start[8];
    size_t start_len = 0;
    build_start_apdu(auth_case, start, &start_len);
    uint8_t response[64];
    size_t response_len = 0;
    exchange(fixture, start, start_len, response, &response_len);
    munit_assert_size(response_len, ==, challenge_length(auth_case) + 2);
    munit_assert_uint8(response[response_len - 2], ==, 0x91);
    munit_assert_uint8(response[response_len - 1], ==, DFC_CMD_ADDITIONAL_FRAME);
    build_continuation_apdu(
        auth_case, fixture->session->emulator, valid, continuation, continuation_len);
    auth_faults_clear();
}

static void assert_authentication_retired(const DfcEmulator* emulator) {
    static const uint8_t zero[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_false(dfc_emulator_native_authentication_active(emulator));
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_encryption_key), emulator->ev2_session_encryption_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_mac_key), emulator->ev2_session_mac_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_transaction_identifier), emulator->ev2_transaction_identifier, zero);
#endif
    assert_pending_cleared(emulator);
}

static MunitResult
    test_continuation_failures_report_memory_error(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t case_index = 0; case_index < auth_case_count; case_index++) {
        auth_faults_clear();
        AuthFixture fixture;
        const AuthCase* auth_case = &auth_cases[case_index];
        auth_fixture_open(&fixture, auth_case);
        uint8_t continuation[38];
        size_t continuation_len = 0;
        begin_authentication(&fixture, auth_case, continuation, &continuation_len, true);

        if(auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY) {
            fail_des_block_call = 1;
        } else if(auth_case->command == DFC_CMD_AUTHENTICATE_ISO) {
            fail_des_cbc_call = 1;
        } else {
            fail_aes_cbc_call = 1;
        }
        uint8_t response[64];
        size_t response_len = 0;
        exchange(&fixture, continuation, continuation_len, response, &response_len);
        assert_status(response, response_len, DFC_STATUS_MEMORY_ERROR);
        assert_authentication_retired(fixture.session->emulator);
        assert_transaction_outcome(auth_case, &fixture);
        auth_fixture_close(&fixture);
    }

    auth_faults_clear();
    return MUNIT_OK;
}

static MunitResult
    test_late_backend_failures_report_memory_error(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    static const struct {
        size_t auth_case;
        size_t failure_kind;
    } failures[] = {
        {0, 0}, // D40 response encryption.
        {1, 0}, // ISO response encryption.
        {2, 0}, // AES response encryption.
        {0, 2}, // D40 session allocation.
        {1, 2}, // ISO session allocation.
        {2, 2}, // AES session allocation.
        {3, 0}, // EV2 response encryption.
        {3, 1}, // EV2 session-key derivation.
        {4, 0}, // EV2 NonFirst response encryption.
    };

    for(size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        auth_faults_clear();
        AuthFixture fixture;
        const AuthCase* auth_case = &auth_cases[failures[i].auth_case];
        auth_fixture_open(&fixture, auth_case);
        uint8_t continuation[38];
        size_t continuation_len = 0;
        begin_authentication(&fixture, auth_case, continuation, &continuation_len, true);

        if(failures[i].failure_kind == 2) {
            dfc_secure_messaging_free(fixture.session->emulator->secure_messaging);
            fixture.session->emulator->secure_messaging = NULL;
            fail_secure_messaging_allocation = true;
        } else if(failures[i].failure_kind == 1) {
            fail_aes_block_call = 1;
        } else if(
            auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY ||
            auth_case->command == DFC_CMD_AUTHENTICATE_ISO) {
            fail_des_cbc_call = 2 - (auth_case->command == DFC_CMD_AUTHENTICATE_LEGACY);
        } else {
            fail_aes_cbc_call = 2;
        }

        uint8_t response[64];
        size_t response_len = 0;
        exchange(&fixture, continuation, continuation_len, response, &response_len);
        assert_status(response, response_len, DFC_STATUS_MEMORY_ERROR);
        assert_authentication_retired(fixture.session->emulator);
        assert_transaction_outcome(auth_case, &fixture);
        auth_fixture_close(&fixture);
    }
    auth_faults_clear();
    return MUNIT_OK;
}

static MunitResult test_bad_cryptograms_remain_authentication_errors(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t case_index = 0; case_index < auth_case_count; case_index++) {
        auth_faults_clear();
        AuthFixture fixture;
        const AuthCase* auth_case = &auth_cases[case_index];
        auth_fixture_open(&fixture, auth_case);
        uint8_t continuation[38];
        size_t continuation_len = 0;
        begin_authentication(&fixture, auth_case, continuation, &continuation_len, false);

        uint8_t response[64];
        size_t response_len = 0;
        exchange(&fixture, continuation, continuation_len, response, &response_len);
        assert_status(response, response_len, DFC_STATUS_AUTHENTICATION_ERR);
        assert_authentication_retired(fixture.session->emulator);
        assert_transaction_outcome(auth_case, &fixture);
        auth_fixture_close(&fixture);
    }
    auth_faults_clear();
    return MUNIT_OK;
}

static MunitResult test_malformed_continuations_remain_authentication_errors(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t case_index = 0; case_index < auth_case_count; case_index++) {
        auth_faults_clear();
        AuthFixture fixture;
        const AuthCase* auth_case = &auth_cases[case_index];
        auth_fixture_open(&fixture, auth_case);
        uint8_t continuation[38];
        size_t continuation_len = 0;
        begin_authentication(&fixture, auth_case, continuation, &continuation_len, true);

        // Keep the APDU framing valid while shortening the authentication
        // payload, so this exercises the family handler rather than transport.
        continuation[4]--;
        continuation_len--;
        continuation[continuation_len - 1] = 0;
        uint8_t response[64];
        size_t response_len = 0;
        exchange(&fixture, continuation, continuation_len, response, &response_len);
        assert_status(response, response_len, DFC_STATUS_AUTHENTICATION_ERR);
        assert_authentication_retired(fixture.session->emulator);
        assert_transaction_outcome(auth_case, &fixture);
        auth_fixture_close(&fixture);
    }
    auth_faults_clear();
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/start-failures-report-memory-error",
     test_start_failures_report_memory_error,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/random-generation-failures-report-memory-error",
     test_random_generation_failures_report_memory_error,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/continuation-failures-report-memory-error",
     test_continuation_failures_report_memory_error,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/late-backend-failures-report-memory-error",
     test_late_backend_failures_report_memory_error,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/bad-cryptograms-remain-authentication-errors",
     test_bad_cryptograms_remain_authentication_errors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/malformed-continuations-remain-authentication-errors",
     test_malformed_continuations_remain_authentication_errors,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_auth_backend_failures", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
