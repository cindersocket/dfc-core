#include "munit/munit.h"

#include "dfc_reader.h"

#include <string.h>

static void assert_ev1_internal_capacity_is_atomic(
    uint8_t cipher,
    size_t key_len,
    uint8_t instruction,
    size_t data_len,
    uint8_t comm_mode) {
    uint8_t key[DFC_MAX_KEY_LEN] = {0};
    DfcReaderSession session;
    dfc_reader_session_init(&session);
    session.auth_mode = cipher;
    munit_assert_true(dfc_secure_messaging_init(&session.sm, cipher, key, key_len, NULL));
    session.sm.pcd = true;
    memset(session.sm.iv, 0x5A, sizeof(session.sm.iv));
    DfcReaderSession before = session;

    DfcCommand command = {.ins = instruction, .data_len = data_len};
    memset(command.data, 0xA5, data_len);
    DfcReaderOptions options = {.comm_mode = comm_mode};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &session, DfcReaderFramingIso7816, &command, &options),
        ==,
        DfcReaderInvalid);
    munit_assert_memory_equal(sizeof(before), &session, &before);
    munit_assert_size(exchange.frame_len, ==, 0);
    munit_assert_memory_equal(sizeof(exchange.frame), exchange.frame, ((uint8_t[16]){0}));
}

static MunitResult
    test_internal_command_capacity_is_invalid(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcReaderSession session;
    dfc_reader_session_init(&session);
    DfcReaderExchange exchange;
    DfcReaderOptions options = {0};
    DfcCommand command = {.ins = DFC_CMD_SELECT_APPLICATION, .data_len = 17};
    memset(command.data, 0xA5, command.data_len);

    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &session, DfcReaderFramingIso7816, &command, &options),
        ==,
        DfcReaderInvalid);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    session.auth_mode = DFC_READER_AUTH_EV2;
    command.ins = DFC_CMD_GET_KEY_SETTINGS;
    command.data_len = 9;
    options.comm_mode = DFC_COMM_MAC;
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &session, DfcReaderFramingIso7816, &command, &options),
        ==,
        DfcReaderInvalid);
#endif

    static const struct {
        uint8_t cipher;
        size_t key_len;
    } ev1_sessions[] = {
        {DFC_CMD_AUTHENTICATE_AES, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 16},
        {DFC_CMD_AUTHENTICATE_ISO, 24},
    };
    for(size_t i = 0; i < sizeof(ev1_sessions) / sizeof(ev1_sessions[0]); i++) {
        assert_ev1_internal_capacity_is_atomic(
            ev1_sessions[i].cipher, ev1_sessions[i].key_len, DFC_CMD_WRITE_DATA, 9, DFC_COMM_MAC);
        assert_ev1_internal_capacity_is_atomic(
            ev1_sessions[i].cipher,
            ev1_sessions[i].key_len,
            DFC_CMD_GET_KEY_SETTINGS,
            17,
            DFC_COMM_PLAIN);
        assert_ev1_internal_capacity_is_atomic(
            ev1_sessions[i].cipher,
            ev1_sessions[i].key_len,
            DFC_CMD_CHANGE_KEY,
            17,
            DFC_COMM_PLAIN);
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/internal-command-capacity",
     test_internal_command_capacity_is_invalid,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/dfc_reader_reduced", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
