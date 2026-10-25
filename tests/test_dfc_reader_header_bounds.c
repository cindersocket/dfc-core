// The clear head of an encrypted file write is a length the caller chooses and
// the reader copies into fixed storage. This suite holds that one length to
// one bound, DFC_READER_MAX_CLEAR_HEADER_LENGTH, at the single entry point every
// binding reaches, and does so exhaustively: every octet value, in every
// session family (an unauthenticated session included), for each way the reader
// treats an instruction's head, in every communication mode. Run under a sanitizer, a length that gets
// past the bound is a stack overwrite the sanitizer names; run without one, it
// is a status the assertions refuse.

#include "dfc_reader_test_link.h"

#include <string.h>

typedef enum {
    AuthNone,
    AuthNative, // DFC_CMD_AUTHENTICATE_*
    AuthEv2First,
} AuthKind;

typedef struct {
    const char* name;
    AuthKind kind;
    const uint8_t* aid;
    uint8_t cipher;
    const uint8_t* key;
    size_t key_len;
} Family;

// One row per session family the reader wraps a head for, plus a session that
// is not authenticated at all: the bound belongs to the option, not to whichever
// session the caller happens to be in.
static const Family FAMILIES[] = {
    {"none", AuthNone, NULL, 0, NULL, 0},
    {"D40", AuthNative, AID_D40, DFC_CMD_AUTHENTICATE_LEGACY, DES_KEY_0, 16},
    {"ISO 2K3DES", AuthNative, AID_ISO, DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0, 16},
    {"ISO 3K3DES", AuthNative, AID_3K, DFC_CMD_AUTHENTICATE_ISO, TDES3_KEY_0, 24},
    {"AES", AuthNative, AID_AES, DFC_CMD_AUTHENTICATE_AES, AES_KEY_0, 16},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"EV2 First", AuthEv2First, AID_AES, 0, AES_KEY_0, 16},
#endif
};

// One instruction per way the reader treats a head: a data or record write
// (seven octets), UpdateRecord (ten, the longest), a value command (one), a
// read, and a command that is no file command at all. Instructions that share
// a path add cases, not coverage.
static const uint8_t INSTRUCTIONS[] = {
    DFC_CMD_WRITE_DATA,
    DFC_CMD_UPDATE_RECORD,
    DFC_CMD_CREDIT,
    DFC_CMD_READ_DATA,
    DFC_CMD_GET_KEY_SETTINGS,
};

static const uint8_t COMM_MODES[] = {DFC_COMM_PLAIN, DFC_COMM_MAC, DFC_COMM_ENCIPHERED};

// Long enough that the head never exceeds the data field for any accepted
// length, so a refusal can only be the bound itself.
#define DATA_LEN 60

static void open_family(Link* link, const Family* family) {
    link_open(link, DfcGenerationEv2, DfcReaderFramingIso7816);
    if(family->kind == AuthNone) return;
    select_app(link, family->aid);
    if(family->kind == AuthEv2First) {
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        munit_assert_int(authenticate_ev2(link, true, 0, family->key), ==, DfcReaderOk);
#endif
    } else {
        munit_assert_int(
            authenticate(link, family->cipher, 0, family->key, family->key_len), ==, DfcReaderOk);
    }
}

// Begin an exchange naming `header_len` and hold the outcome to the contract:
// within the bound the reader accepts it; beyond it the reader refuses before
// the exchange or the session is touched.
static void check_header_len(Link* link, uint8_t ins, uint8_t comm, size_t header_len) {
    uint8_t data[DATA_LEN];
    memset(data, 0x41, sizeof(data));
    DfcCommand command;
    munit_assert_int(dfc_command_encode_raw(&command, ins, data, sizeof(data)), ==, DfcCommandOk);

    DfcReaderOptions options = {0};
    options.comm_mode = comm;
    options.has_header_len = true;
    options.header_len = (uint8_t)header_len;

    DfcReaderSession session_before = link->session;
    DfcReaderExchange exchange;
    memset(&exchange, 0xA5, sizeof(exchange));
    DfcReaderExchange exchange_before = exchange;

    DfcReaderStatus status =
        dfc_reader_exchange_begin(&exchange, &link->session, link->framing, &command, &options);

    if(header_len > DFC_READER_MAX_CLEAR_HEADER_LENGTH) {
        munit_assert_int(status, ==, DfcReaderInvalid);
        munit_assert_memory_equal(sizeof(session_before), &session_before, &link->session);
        munit_assert_memory_equal(sizeof(exchange_before), &exchange_before, &exchange);
    } else {
        munit_assert_int(status, ==, DfcReaderOk);
    }
}

static MunitResult
    test_every_header_length_in_every_session(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    static Link link;
    for(size_t f = 0; f < sizeof(FAMILIES) / sizeof(FAMILIES[0]); f++) {
        open_family(&link, &FAMILIES[f]);
        for(size_t i = 0; i < sizeof(INSTRUCTIONS); i++) {
            for(size_t m = 0; m < sizeof(COMM_MODES); m++) {
                for(size_t header_len = 0; header_len <= UINT8_MAX; header_len++) {
                    check_header_len(&link, INSTRUCTIONS[i], COMM_MODES[m], header_len);
                }
            }
        }
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/every-header-length-in-every-session",
     test_every_header_length_in_every_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_reader_header_bounds", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
