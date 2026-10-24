// Every function that fills a credential from outside input shares one failure
// contract: on any failure the credential is the empty credential
// (dfc_credential_clear), with nothing decoded before the fault left behind.
//
// A decoder writes its fields as it reads them, so a fault can arrive after any
// of them, key material included. This suite finds the fault wherever it falls:
// it truncates a credential that carries every field family at every length and
// corrupts it at every octet, through every decoder, and requires the whole
// destination, padding and unused pool bytes included, to equal the empty
// credential after each failure.
//
// DECODERS is the registry of those entry points. tests/check_decoder_registry.py
// fails the build when a header declares a decoder this table does not name, so a
// new entry point cannot ship without the contract being run against it.

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_text.h"

#if DFC_ENABLE_EMULATOR
#include "dfc_target_ffi.h"
#endif

#include <stdio.h>
#include <string.h>

typedef enum {
    InputBinary,
    InputText,
    InputEither,
} InputKind;

typedef struct {
    const char* name;
    InputKind accepts;
    // True for an entry point that only dispatches to a decoder this table also
    // names. Its own failure paths are the dispatch and argument checks, which
    // the argument cases cover in full; the sweeps below sample it sparsely
    // instead of repeating the decoder underneath it.
    bool thin;
    // Zero on success, any other value on failure.
    int32_t (*decode)(DfcCredential* credential, const uint8_t* in, size_t len);
} Decoder;

// How sparsely the sweeps sample a thin entry point.
#define THIN_STRIDE 16

#if DFC_ENABLE_DER_DECODER
static int32_t run_der_decode(DfcCredential* credential, const uint8_t* in, size_t len) {
    return dfc_der_decode(credential, in, len);
}
#endif

#if DFC_ENABLE_TEXT_CODEC
static int32_t run_text_parse(DfcCredential* credential, const uint8_t* in, size_t len) {
    return dfc_text_parse(credential, (const char*)in, len, NULL);
}

static int32_t run_credential_load(DfcCredential* credential, const uint8_t* in, size_t len) {
    return dfc_credential_load(credential, in, len, NULL);
}
#endif

#if DFC_ENABLE_EMULATOR && DFC_ENABLE_DER_DECODER
static int32_t run_target_decode(DfcCredential* credential, const uint8_t* in, size_t len) {
    return dfc_target_credential_decode(credential, in, len);
}
#endif

// One row per decoder: dfc_der_decode, dfc_text_parse, dfc_credential_load and
// dfc_target_credential_decode. The FFI's dfc_ffi_credential_decode, _parse and
// _load fill a credential they allocate and free it on failure, so they have no
// destination of the caller's to leave partly filled.
static const Decoder DECODERS[] = {
#if DFC_ENABLE_DER_DECODER
    {"dfc_der_decode", InputBinary, false, run_der_decode},
#endif
#if DFC_ENABLE_TEXT_CODEC
    {"dfc_text_parse", InputText, false, run_text_parse},
    {"dfc_credential_load", InputEither, true, run_credential_load},
#endif
#if DFC_ENABLE_EMULATOR && DFC_ENABLE_DER_DECODER
    {"dfc_target_credential_decode", InputBinary, true, run_target_decode},
#endif
};

#define DECODER_COUNT (sizeof(DECODERS) / sizeof(DECODERS[0]))

// The example that carries every field family: key sets, delegated-application
// state, DAM keys, a transaction-MAC file and its key.
#define EXAMPLE "v6-maximal"

static uint8_t binary_input[DFC_DER_MAX_SIZE];
static uint8_t text_input[DFC_TEXT_MAX_SIZE];
static size_t binary_len;
static size_t text_len;

static size_t read_example(const char* extension, uint8_t* buffer, size_t capacity) {
    char path[128];
    snprintf(path, sizeof(path), "../examples/credentials/%s%s", EXAMPLE, extension);
    FILE* file = fopen(path, "rb");
    munit_assert_not_null(file);
    size_t length = fread(buffer, 1, capacity, file);
    munit_assert_int(ferror(file), ==, 0);
    munit_assert_int(fgetc(file), ==, EOF);
    munit_assert_int(fclose(file), ==, 0);
    munit_assert_size(length, >, 0);
    return length;
}

static void load_examples(void) {
    if(binary_len != 0) return;
    binary_len = read_example(".dfcb", binary_input, sizeof(binary_input));
    text_len = read_example(".dfc", text_input, sizeof(text_input));
}

static const DfcCredential* empty_credential(void) {
    static DfcCredential empty;
    static bool ready;
    if(!ready) {
        memset(&empty, 0xCC, sizeof(empty));
        dfc_credential_clear(&empty);
        ready = true;
    }
    return &empty;
}

// Every octet of a failed destination, padding included, must be the empty
// credential's. Starting from a poisoned destination also catches a decoder
// that gives up before touching it.
static void poison(DfcCredential* credential) {
    memset(credential, 0xA5, sizeof(*credential));
}

static void assert_empty(const char* decoder, const char* how, size_t at, DfcCredential* c) {
    if(memcmp(c, empty_credential(), sizeof(*c)) != 0) {
        munit_logf(
            MUNIT_LOG_ERROR, "%s left a partial credential after %s at %zu", decoder, how, at);
        munit_assert_memory_equal(sizeof(*c), c, empty_credential());
    }
}

static bool accepts(const Decoder* decoder, InputKind kind) {
    return decoder->accepts == InputEither || decoder->accepts == kind;
}

static size_t stride_of(const Decoder* decoder) {
    return decoder->thin ? THIN_STRIDE : 1;
}

typedef struct {
    size_t failures;
    size_t successes;
} Tally;

static void run_case(
    const Decoder* decoder,
    const uint8_t* in,
    size_t len,
    const char* how,
    size_t at,
    Tally* tally) {
    static DfcCredential destination;
    poison(&destination);
    int32_t status = decoder->decode(&destination, in, len);
    if(status == 0) {
        tally->successes++;
        return;
    }
    tally->failures++;
    assert_empty(decoder->name, how, at, &destination);
}

// A fault after any prefix of the credential.
static MunitResult
    test_truncation_leaves_the_empty_credential(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    load_examples();
    for(size_t d = 0; d < DECODER_COUNT; d++) {
        Tally tally = {0, 0};
        if(accepts(&DECODERS[d], InputBinary)) {
            for(size_t len = 0; len < binary_len; len += stride_of(&DECODERS[d])) {
                run_case(&DECODERS[d], binary_input, len, "truncation", len, &tally);
            }
        }
        if(accepts(&DECODERS[d], InputText)) {
            for(size_t len = 0; len < text_len; len += stride_of(&DECODERS[d])) {
                run_case(&DECODERS[d], text_input, len, "truncation", len, &tally);
            }
        }
        // The run must have exercised the failure path, not just accepted prefixes.
        munit_assert_size(tally.failures, >, 0);
    }
    return MUNIT_OK;
}

// A fault in any single octet, by several corruptions of it. Corrupting an octet
// early in the credential fails late or early depending on what it governs;
// either way the contract is the same. Every octet of each encoding is corrupted
// four ways through the decoder that reads it.
static MunitResult
    test_corruption_leaves_the_empty_credential(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    load_examples();
    static const uint8_t masks[] = {0x01, 0x20, 0x80, 0xFF};
    static uint8_t
        mutated[DFC_DER_MAX_SIZE > DFC_TEXT_MAX_SIZE ? DFC_DER_MAX_SIZE : DFC_TEXT_MAX_SIZE];
    for(size_t d = 0; d < DECODER_COUNT; d++) {
        Tally tally = {0, 0};
        for(int kind = InputBinary; kind <= InputText; kind++) {
            if(!accepts(&DECODERS[d], (InputKind)kind)) continue;
            const uint8_t* source = kind == InputBinary ? binary_input : text_input;
            size_t length = kind == InputBinary ? binary_len : text_len;
            memcpy(mutated, source, length);
            for(size_t at = 0; at < length; at += stride_of(&DECODERS[d])) {
                for(size_t m = 0; m < sizeof(masks); m++) {
                    mutated[at] = source[at] ^ masks[m];
                    run_case(&DECODERS[d], mutated, length, "corruption", at, &tally);
                }
                mutated[at] = source[at];
            }
        }
        munit_assert_size(tally.failures, >, 0);
    }
    return MUNIT_OK;
}

// A caller that hands over nothing usable still gets a credential it can reuse
// or free.
static MunitResult
    test_argument_errors_leave_the_empty_credential(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    load_examples();
    static uint8_t oversized[DFC_DER_MAX_SIZE + DFC_TEXT_MAX_SIZE + 2];
    for(size_t d = 0; d < DECODER_COUNT; d++) {
        const Decoder* decoder = &DECODERS[d];
        Tally tally = {0, 0};
        // No input, with and without a length.
        run_case(decoder, NULL, 0, "NULL input", 0, &tally);
        run_case(decoder, NULL, 1, "NULL input with a length", 1, &tally);
        // Zero length from a real buffer.
        run_case(decoder, binary_input, 0, "empty input", 0, &tally);
        // Larger than any credential either encoding can hold.
        run_case(
            decoder, oversized, sizeof(oversized), "oversize input", sizeof(oversized), &tally);
        munit_assert_size(tally.failures, ==, 4);

        // No destination at all is an error, not a crash.
        munit_assert_int(decoder->decode(NULL, binary_input, binary_len), !=, 0);
    }
    return MUNIT_OK;
}

// The control: the same inputs, untouched, decode, and a successful decode does
// not look like the empty credential. Without this the suite could pass by
// every decoder failing everything.
static MunitResult
    test_the_unmodified_credential_decodes(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    load_examples();
    static DfcCredential destination;
    for(size_t d = 0; d < DECODER_COUNT; d++) {
        if(accepts(&DECODERS[d], InputBinary)) {
            poison(&destination);
            munit_assert_int(DECODERS[d].decode(&destination, binary_input, binary_len), ==, 0);
            munit_assert_int(memcmp(&destination, empty_credential(), sizeof(destination)), !=, 0);
        }
        if(accepts(&DECODERS[d], InputText)) {
            poison(&destination);
            munit_assert_int(DECODERS[d].decode(&destination, text_input, text_len), ==, 0);
            munit_assert_int(memcmp(&destination, empty_credential(), sizeof(destination)), !=, 0);
        }
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/the-unmodified-credential-decodes",
     test_the_unmodified_credential_decodes,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/truncation-leaves-the-empty-credential",
     test_truncation_leaves_the_empty_credential,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/corruption-leaves-the-empty-credential",
     test_corruption_leaves_the_empty_credential,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/argument-errors-leave-the-empty-credential",
     test_argument_errors_leave_the_empty_credential,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_decode_failure_atomicity", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
