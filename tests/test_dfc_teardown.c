#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_command.h"
#include "dfc_emulator.h"
#include "dfc_emulator_i.h"
#include "dfc_port.h"
#include "dfc_port_host.h"
#include "dfc_reader.h"
#include "dfc_virtual_picc.h"

#include <string.h>

typedef struct {
    const void* pointer;
    size_t length;
    bool observed;
    bool zeroed;
} FreedRegion;

typedef struct {
    FreedRegion regions[3];
    size_t count;
} FreeAudit;

typedef struct {
    size_t count;
    bool zeroed;
} ByteBufFreeAudit;

static void observe_freed_region(const void* pointer, void* context) {
    FreeAudit* audit = context;
    for(size_t region_index = 0; region_index < audit->count; region_index++) {
        FreedRegion* region = &audit->regions[region_index];
        if(region->pointer != pointer) continue;
        region->observed = true;
        region->zeroed = true;
        const uint8_t* bytes = pointer;
        for(size_t byte_index = 0; byte_index < region->length; byte_index++) {
            if(bytes[byte_index] != 0) region->zeroed = false;
        }
    }
}

static void observe_freed_bytebuf(const void* pointer, void* context) {
    ByteBufFreeAudit* audit = context;
    audit->count++;
    audit->zeroed = true;
    const uint8_t* bytes = pointer;
    for(size_t index = 0; index < sizeof(DfcByteBuf); index++) {
        if(bytes[index] != 0) audit->zeroed = false;
    }
}

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* picc;
    DfcReaderSession reader;
} ReaderAuthAudit;

static const uint8_t AuditAesKey[DFC_AES_KEY_LENGTH] =
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const uint8_t AuditDesKey[DFC_AES_KEY_LENGTH] =
    {0xC6, 0xEF, 0x84, 0x7C, 0xAE, 0x0A, 0x2A, 0x56, 0xC0, 0x19, 0x2A, 0xA1, 0xC4, 0xE8, 0xD9, 0xFB};

static DfcReaderStatus reader_auth_audit_run(ReaderAuthAudit* audit, DfcReaderExchange* exchange) {
    uint8_t command[DFC_COMMAND_MAX_APDU];
    uint8_t response[DFC_READER_MAX_RESPONSE + 16];
    size_t command_len = 0;
    size_t response_len = 0;
    const uint8_t* answer = NULL;
    DfcReaderStatus status;
    while((status = dfc_reader_step(
               exchange, answer, response_len, command, sizeof(command), &command_len)) ==
          DfcReaderPending) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                audit->picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        answer = response;
    }
    return status;
}

static void reader_auth_audit_open(
    ReaderAuthAudit* audit,
    DfcGeneration generation,
    uint8_t key_settings,
    uint8_t preferred_authentication,
    const uint8_t* key,
    size_t key_len) {
    memset(audit, 0, sizeof(*audit));
    munit_assert_true(dfc_credential_clear(&audit->credential));
    audit->credential.card.generation = generation;
    audit->credential.card.storage = 4096;
    memcpy(audit->credential.uid, "\x04\x11\x22\x33\x44\x55\x66", DFC_DESFIRE_UID_LEN);
    audit->credential.uid_len = DFC_DESFIRE_UID_LEN;
    const uint8_t wire_aid[3] = {3, 2, 1};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &audit->credential, wire_aid, 0x0F, key_settings | 1);
    munit_assert_not_null(app);
    app->auth_command = preferred_authentication;
    app->has_auth_commands = true;
    app->auth_commands = DFC_AUTH_COMMAND_ALL;
    munit_assert_size(app->key_len, ==, key_len);
    memcpy(dfc_credential_key(&audit->credential, app, 0), key, key_len);
    audit->picc = dfc_virtual_picc_session_alloc(&audit->credential);
    munit_assert_not_null(audit->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(audit->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&audit->reader);

    DfcCommand select;
    const uint8_t human_aid[3] = {1, 2, 3};
    munit_assert_int(dfc_command_select_application(&select, human_aid, NULL), ==, DfcCommandOk);
    DfcReaderExchange exchange;
    DfcReaderOptions options = {0};
    munit_assert_int(
        dfc_reader_exchange_begin(
            &exchange, &audit->reader, DfcReaderFramingIso7816, &select, &options),
        ==,
        DfcReaderOk);
    munit_assert_int(reader_auth_audit_run(audit, &exchange), ==, DfcReaderOk);
}

static void reader_auth_audit_close(ReaderAuthAudit* audit) {
    dfc_virtual_picc_session_free(audit->picc);
}

static void assert_reader_auth_transients_wiped(const DfcReaderExchange* exchange) {
    const uint8_t zero[DFC_MAX_KEY_LEN] = {0};
    munit_assert_memory_equal(sizeof(exchange->auth_key), exchange->auth_key, zero);
    munit_assert_memory_equal(sizeof(exchange->auth_random_a), exchange->auth_random_a, zero);
    munit_assert_memory_equal(sizeof(exchange->auth_random_b), exchange->auth_random_b, zero);
#if DFC_ENABLE_ISO7816_AUTH
    munit_assert_memory_equal(
        sizeof(exchange->auth_random_second), exchange->auth_random_second, zero);
#endif
    munit_assert_memory_equal(sizeof(exchange->auth_iv), exchange->auth_iv, zero);
    munit_assert_memory_equal(
        sizeof(exchange->auth_capabilities), exchange->auth_capabilities, zero);
    munit_assert_size(exchange->auth_key_len, ==, 0);
    munit_assert_size(exchange->auth_challenge_len, ==, 0);
    munit_assert_uint8(exchange->auth_cipher, ==, 0);
    munit_assert_uint8(exchange->auth_key_no, ==, 0);
#if DFC_ENABLE_ISO7816_AUTH
    munit_assert_uint8(exchange->auth_reference, ==, 0);
    munit_assert_uint8(exchange->auth_algorithm, ==, 0);
#endif
    munit_assert_false(exchange->auth_first);
}

static void reader_auth_audit_seed_ev2(ReaderAuthAudit* audit) {
    DfcEmulator* emulator = audit->picc->emulator;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 7;
    memset(
        emulator->ev2_transaction_identifier, 0x31, sizeof(emulator->ev2_transaction_identifier));
    memset(
        emulator->ev2_session_encryption_key, 0x32, sizeof(emulator->ev2_session_encryption_key));
    memset(emulator->ev2_session_mac_key, 0x33, sizeof(emulator->ev2_session_mac_key));
    memset(emulator->ev2_card_capabilities, 0x34, sizeof(emulator->ev2_card_capabilities));
    memset(emulator->ev2_reader_capabilities, 0x35, sizeof(emulator->ev2_reader_capabilities));
    emulator->ev2_command_counter = 9;

    dfc_reader_session_init(&audit->reader);
    audit->reader.auth_mode = DFC_READER_AUTH_EV2;
    audit->reader.key_no = 7;
    memset(
        audit->reader.ev2_transaction_identifier,
        0x31,
        sizeof(audit->reader.ev2_transaction_identifier));
    memset(audit->reader.ev2_encryption_key, 0x32, sizeof(audit->reader.ev2_encryption_key));
    memset(audit->reader.ev2_mac_key, 0x33, sizeof(audit->reader.ev2_mac_key));
    memset(audit->reader.ev2_card_capabilities, 0x34, sizeof(audit->reader.ev2_card_capabilities));
    memset(
        audit->reader.ev2_reader_capabilities,
        0x35,
        sizeof(audit->reader.ev2_reader_capabilities));
    audit->reader.ev2_command_counter = 9;
}

static DfcReaderStatus reader_auth_audit_native(
    ReaderAuthAudit* audit,
    DfcReaderExchange* exchange,
    uint8_t cipher,
    const uint8_t* key,
    size_t key_len) {
    uint8_t random_a[DFC_EV2_RANDOM_LENGTH];
    for(size_t i = 0; i < sizeof(random_a); i++)
        random_a[i] = (uint8_t)(0xA0 + i);
    munit_assert_int(
        dfc_reader_authenticate_begin(
            exchange,
            &audit->reader,
            DfcReaderFramingIso7816,
            cipher,
            0,
            key,
            key_len,
            random_a,
            dfc_reader_challenge_length(cipher, key_len)),
        ==,
        DfcReaderOk);
    return reader_auth_audit_run(audit, exchange);
}

#if DFC_ENABLE_ISO7816_AUTH
static DfcReaderStatus reader_auth_audit_iso7816(
    ReaderAuthAudit* audit,
    DfcReaderExchange* exchange,
    const uint8_t key[DFC_AES_KEY_LENGTH]) {
    const uint8_t random_first[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    const uint8_t random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            exchange,
            &audit->reader,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            key,
            DFC_AES_KEY_LENGTH,
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            random_first,
            random_second,
            sizeof(random_first)),
        ==,
        DfcReaderOk);
    return reader_auth_audit_run(audit, exchange);
}
#endif

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static DfcReaderStatus reader_auth_audit_ev2(
    ReaderAuthAudit* audit,
    DfcReaderExchange* exchange,
    const uint8_t key[DFC_AES_KEY_LENGTH],
    bool first) {
    const uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0xA3};
    const uint8_t capabilities[DFC_EV2_CAPABILITY_LENGTH] = {1, 2, 3, 4, 5, 6};
    munit_assert_int(
        dfc_reader_authenticate_ev2_begin(
            exchange,
            &audit->reader,
            DfcReaderFramingIso7816,
            first,
            0,
            key,
            random_a,
            first ? capabilities : NULL,
            first ? sizeof(capabilities) : 0),
        ==,
        DfcReaderOk);
    return reader_auth_audit_run(audit, exchange);
}
#endif

static void assert_emulator_ev2_retired(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_false(emulator->ev2_session_active);
    munit_assert_uint8(emulator->ev2_authenticated_key_no, ==, 0);
    munit_assert_uint16(emulator->ev2_command_counter, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_transaction_identifier), emulator->ev2_transaction_identifier, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_encryption_key), emulator->ev2_session_encryption_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_session_mac_key), emulator->ev2_session_mac_key, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_card_capabilities), emulator->ev2_card_capabilities, zero);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_reader_capabilities), emulator->ev2_reader_capabilities, zero);
}

static void assert_reader_session_retired(const DfcReaderSession* reader) {
    DfcReaderSession clear;
    dfc_reader_session_init(&clear);
    munit_assert_memory_equal(sizeof(clear), reader, &clear);
}

static void assert_emulator_authentication_retired(const DfcEmulator* emulator) {
    munit_assert_false(dfc_emulator_native_authentication_active(emulator));
    if(emulator->secure_messaging) {
        munit_assert_memory_equal(
            sizeof(*emulator->secure_messaging),
            emulator->secure_messaging,
            ((uint8_t[sizeof(*emulator->secure_messaging)]){0}));
    }
    munit_assert_uint8(emulator->auth_cipher, ==, 0);
    munit_assert_uint8(emulator->auth_key_no, ==, 0);
    assert_emulator_ev2_retired(emulator);
}

static MunitResult test_reader_authentication_transients_and_family_commit(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;
    static const struct {
        uint8_t cipher;
        DfcGeneration generation;
        uint8_t key_settings;
        const uint8_t* key;
        size_t key_len;
    } native_cases[] = {
        {DFC_CMD_AUTHENTICATE_LEGACY,
         DfcGenerationEv3,
         DFC_KEY_TYPE_DES_2K3DES,
         AuditDesKey,
         sizeof(AuditDesKey)},
        {DFC_CMD_AUTHENTICATE_ISO,
         DfcGenerationEv3,
         DFC_KEY_TYPE_DES_2K3DES,
         AuditDesKey,
         sizeof(AuditDesKey)},
        {DFC_CMD_AUTHENTICATE_AES,
         DfcGenerationEv3,
         DFC_KEY_TYPE_AES,
         AuditAesKey,
         sizeof(AuditAesKey)},
    };
    const uint8_t wrong_key[DFC_AES_KEY_LENGTH] = {0xFF};

    for(size_t i = 0; i < sizeof(native_cases) / sizeof(native_cases[0]); i++) {
        ReaderAuthAudit audit;
        reader_auth_audit_open(
            &audit,
            native_cases[i].generation,
            native_cases[i].key_settings,
            native_cases[i].cipher,
            native_cases[i].key,
            native_cases[i].key_len);
        reader_auth_audit_seed_ev2(&audit);
        DfcReaderExchange exchange;
        DfcReaderStatus cross_family_failure = reader_auth_audit_native(
            &audit, &exchange, native_cases[i].cipher, wrong_key, native_cases[i].key_len);
        munit_assert_int(cross_family_failure, !=, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);

        munit_assert_int(
            reader_auth_audit_native(
                &audit,
                &exchange,
                native_cases[i].cipher,
                native_cases[i].key,
                native_cases[i].key_len),
            ==,
            DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        munit_assert_uint8(audit.reader.auth_mode, ==, native_cases[i].cipher);
        munit_assert_not_null(audit.picc->emulator->secure_messaging);
        munit_assert_uint8(audit.picc->emulator->auth_cipher, ==, native_cases[i].cipher);
        assert_emulator_ev2_retired(audit.picc->emulator);

        DfcReaderStatus failure = reader_auth_audit_native(
            &audit, &exchange, native_cases[i].cipher, wrong_key, native_cases[i].key_len);
        munit_assert_int(failure, !=, DfcReaderOk);
        munit_assert_int(failure, !=, DfcReaderPending);
        munit_assert_int(failure, !=, DfcReaderBufferTooSmall);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);
        reader_auth_audit_close(&audit);
    }

#if DFC_ENABLE_ISO7816_AUTH
    {
        ReaderAuthAudit audit;
        reader_auth_audit_open(
            &audit,
            DfcGenerationEv3,
            DFC_KEY_TYPE_AES,
            DFC_CMD_AUTHENTICATE_AES,
            AuditAesKey,
            sizeof(AuditAesKey));
        reader_auth_audit_seed_ev2(&audit);
        DfcReaderExchange exchange;
        DfcReaderStatus cross_family_failure =
            reader_auth_audit_iso7816(&audit, &exchange, wrong_key);
        munit_assert_int(cross_family_failure, !=, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);

        munit_assert_int(
            reader_auth_audit_iso7816(&audit, &exchange, AuditAesKey), ==, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        munit_assert_uint8(audit.reader.auth_mode, ==, DFC_CMD_AUTHENTICATE_AES);
        munit_assert_not_null(audit.picc->emulator->secure_messaging);
        assert_emulator_ev2_retired(audit.picc->emulator);

        DfcReaderStatus failure = reader_auth_audit_iso7816(&audit, &exchange, wrong_key);
        munit_assert_int(failure, !=, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);
        reader_auth_audit_close(&audit);
    }
#endif

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {
        ReaderAuthAudit audit;
        reader_auth_audit_open(
            &audit,
            DfcGenerationEv3,
            DFC_KEY_TYPE_AES,
            DFC_CMD_AUTHENTICATE_AES,
            AuditAesKey,
            sizeof(AuditAesKey));
        DfcReaderExchange exchange;
        munit_assert_int(
            reader_auth_audit_native(
                &audit, &exchange, DFC_CMD_AUTHENTICATE_AES, AuditAesKey, sizeof(AuditAesKey)),
            ==,
            DfcReaderOk);
        munit_assert_not_null(audit.picc->emulator->secure_messaging);
        DfcReaderStatus cross_family_failure =
            reader_auth_audit_ev2(&audit, &exchange, wrong_key, true);
        munit_assert_int(cross_family_failure, !=, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);

        munit_assert_int(
            reader_auth_audit_ev2(&audit, &exchange, AuditAesKey, true), ==, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        munit_assert_uint8(audit.reader.auth_mode, ==, DFC_READER_AUTH_EV2);
        munit_assert_memory_equal(
            sizeof(audit.reader.sm.session_key),
            audit.reader.sm.session_key,
            ((uint8_t[sizeof(audit.reader.sm.session_key)]){0}));
        munit_assert_not_null(audit.picc->emulator->secure_messaging);
        munit_assert_false(dfc_emulator_native_authentication_active(audit.picc->emulator));
        munit_assert_uint8(audit.picc->emulator->auth_cipher, ==, 0);
        munit_assert_uint8(audit.picc->emulator->auth_key_no, ==, 0);
        munit_assert_memory_equal(
            sizeof(audit.picc->emulator->rnd_a),
            audit.picc->emulator->rnd_a,
            ((uint8_t[sizeof(audit.picc->emulator->rnd_a)]){0}));
        munit_assert_true(audit.picc->emulator->ev2_session_active);

        DfcReaderStatus failure = reader_auth_audit_ev2(&audit, &exchange, wrong_key, false);
        munit_assert_int(failure, !=, DfcReaderOk);
        assert_reader_auth_transients_wiped(&exchange);
        assert_reader_session_retired(&audit.reader);
        assert_emulator_authentication_retired(audit.picc->emulator);
        reader_auth_audit_close(&audit);
    }
#endif
    return MUNIT_OK;
}

static MunitResult
    test_emulator_owned_storage_wiped_before_free(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);

    const size_t command_length = 37;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_len = command_length;
    emulator->command_chain_expected = command_length;
    memset(emulator->command_chain, 0xA5, command_length);
    memset(emulator->pending_chain, 0xB4, sizeof(emulator->pending_chain));
    memset(emulator->pending_chain_chunks, 0x4B, sizeof(emulator->pending_chain_chunks));
#if DFC_ENABLE_PROXIMITY_CHECK
    memset(emulator->proximity_random, 0xC6, sizeof(emulator->proximity_random));
    memset(emulator->proximity_published, 0x6C, sizeof(emulator->proximity_published));
    memset(emulator->proximity_transcript, 0xD7, sizeof(emulator->proximity_transcript));
#endif
#if DFC_ENABLE_SDM
    emulator->sdm_read_cache_valid = true;
    emulator->sdm_read_cache_file_number = 7;
    emulator->sdm_read_cache_len = sizeof(emulator->sdm_read_cache);
    memset(emulator->sdm_read_cache, 0xE8, sizeof(emulator->sdm_read_cache));
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    emulator->transaction_input_len = sizeof(emulator->transaction_input);
    memset(emulator->transaction_input, 0xF9, sizeof(emulator->transaction_input));
#endif
    emulator->awaiting_step2 = true;
    emulator->pending_auth_cipher = 0xAA;
    emulator->pending_auth_key_no = 0x5A;
    memset(emulator->rnd_b, 0xC3, sizeof(emulator->rnd_b));
    memset(emulator->enc_rnd_b, 0x3C, sizeof(emulator->enc_rnd_b));
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    emulator->ev2_authentication_pending = true;
    emulator->ev2_pending_authenticated_key_no = 0x5A;
    memset(emulator->ev2_static_key, 0xC3, sizeof(emulator->ev2_static_key));
    memset(emulator->ev2_random_b, 0x3C, sizeof(emulator->ev2_random_b));
    memset(
        emulator->ev2_pending_transaction_identifier,
        0xA5,
        sizeof(emulator->ev2_pending_transaction_identifier));
    memset(
        emulator->ev2_pending_card_capabilities,
        0x5A,
        sizeof(emulator->ev2_pending_card_capabilities));
    memset(
        emulator->ev2_pending_reader_capabilities,
        0x96,
        sizeof(emulator->ev2_pending_reader_capabilities));
#endif

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    const size_t snapshot_length = 43;
    emulator->transaction_snapshot_pool = dfc_platform_alloc(snapshot_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    emulator->transaction_snapshot_pool_length = snapshot_length;
    memset(emulator->transaction_snapshot_pool, 0x5A, snapshot_length);
#else
    const size_t snapshot_length = 0;
#endif

    memset(emulator->rnd_b, 0xC3, sizeof(emulator->rnd_b));
    FreeAudit audit = {
        .regions =
            {
                {emulator->command_chain, command_length, false, false},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
                {emulator->transaction_snapshot_pool, snapshot_length, false, false},
#else
                {NULL, snapshot_length, true, true},
#endif
                {emulator, sizeof(*emulator), false, false},
            },
        .count = 3,
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_free(emulator);
    dfc_host_set_free_observer(NULL, NULL);

    for(size_t index = 0; index < 3; index++) {
        munit_assert_true(audit.regions[index].observed);
        munit_assert_true(audit.regions[index].zeroed);
    }
    return MUNIT_OK;
}

static MunitResult
    test_session_reset_wipes_command_chain(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    const size_t command_length = 29;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_active = true;
    emulator->command_chain_len = command_length;
    emulator->command_chain_expected = command_length;
    memset(emulator->command_chain, 0xA5, command_length);
    memset(emulator->pending_chain, 0xB4, sizeof(emulator->pending_chain));
    memset(emulator->pending_chain_chunks, 0x4B, sizeof(emulator->pending_chain_chunks));
    emulator->pending_chain_len = 37;
    emulator->pending_chain_chunk_count = 3;
#if DFC_ENABLE_SDM
    emulator->sdm_read_cache_valid = true;
    emulator->sdm_read_cache_file_number = 7;
    emulator->sdm_read_cache_len = sizeof(emulator->sdm_read_cache);
    memset(emulator->sdm_read_cache, 0xE8, sizeof(emulator->sdm_read_cache));
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    emulator->transaction_input_len = 17;
    memset(emulator->transaction_input, 0xF9, sizeof(emulator->transaction_input));
#endif

    FreeAudit audit = {
        .regions = {{emulator->command_chain, command_length, false, false}},
        .count = 1,
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_reset_session(emulator);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.regions[0].observed);
    munit_assert_true(audit.regions[0].zeroed);
    munit_assert_null(emulator->command_chain);
    munit_assert_false(emulator->awaiting_step2);
    munit_assert_uint8(emulator->pending_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->pending_auth_key_no, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->rnd_b), emulator->rnd_b, ((uint8_t[sizeof(emulator->rnd_b)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->enc_rnd_b),
        emulator->enc_rnd_b,
        ((uint8_t[sizeof(emulator->enc_rnd_b)]){0}));
    for(size_t index = 0; index < sizeof(emulator->pending_chain); index++) {
        munit_assert_uint8(emulator->pending_chain[index], ==, index < 37 ? 0 : 0xB4);
    }
    for(size_t index = 0; index < sizeof(emulator->pending_chain_chunks); index++) {
        munit_assert_uint8(emulator->pending_chain_chunks[index], ==, index < 3 ? 0 : 0x4B);
    }
#if DFC_ENABLE_PROXIMITY_CHECK
    munit_assert_memory_equal(
        sizeof(emulator->proximity_random),
        emulator->proximity_random,
        ((uint8_t[sizeof(emulator->proximity_random)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->proximity_published),
        emulator->proximity_published,
        ((uint8_t[sizeof(emulator->proximity_published)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->proximity_transcript),
        emulator->proximity_transcript,
        ((uint8_t[sizeof(emulator->proximity_transcript)]){0}));
#endif
#if DFC_ENABLE_SDM
    munit_assert_false(emulator->sdm_read_cache_valid);
    munit_assert_uint8(emulator->sdm_read_cache_file_number, ==, 0);
    munit_assert_size(emulator->sdm_read_cache_len, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->sdm_read_cache),
        emulator->sdm_read_cache,
        ((uint8_t[sizeof(emulator->sdm_read_cache)]){0}));
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    munit_assert_size(emulator->transaction_input_len, ==, 0);
    for(size_t index = 0; index < sizeof(emulator->transaction_input); index++) {
        munit_assert_uint8(emulator->transaction_input[index], ==, index < 17 ? 0 : 0xF9);
    }
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    munit_assert_false(emulator->ev2_authentication_pending);
    munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->ev2_static_key),
        emulator->ev2_static_key,
        ((uint8_t[sizeof(emulator->ev2_static_key)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->ev2_random_b),
        emulator->ev2_random_b,
        ((uint8_t[sizeof(emulator->ev2_random_b)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->ev2_pending_transaction_identifier),
        emulator->ev2_pending_transaction_identifier,
        ((uint8_t[sizeof(emulator->ev2_pending_transaction_identifier)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->ev2_pending_card_capabilities),
        emulator->ev2_pending_card_capabilities,
        ((uint8_t[sizeof(emulator->ev2_pending_card_capabilities)]){0}));
    munit_assert_memory_equal(
        sizeof(emulator->ev2_pending_reader_capabilities),
        emulator->ev2_pending_reader_capabilities,
        ((uint8_t[sizeof(emulator->ev2_pending_reader_capabilities)]){0}));
#endif
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult test_activation_reset_wipes_retained_and_released_storage(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    const size_t command_length = 31;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_len = command_length;
    memset(emulator->command_chain, 0xA5, command_length);

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    const size_t snapshot_length = 41;
    emulator->transaction_snapshot_pool = dfc_platform_alloc(snapshot_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    emulator->transaction_snapshot_pool_length = snapshot_length;
    memset(emulator->transaction_snapshot_pool, 0x5A, snapshot_length);
#endif
    memset(emulator->rnd_b, 0xC3, sizeof(emulator->rnd_b));
    memset(emulator->tx_buffer, 0x3C, sizeof(*emulator->tx_buffer));

    FreeAudit audit = {
        .regions =
            {
                {emulator->command_chain, command_length, false, false},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
                {emulator->transaction_snapshot_pool, snapshot_length, false, false},
#endif
            },
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
        .count = 2,
#else
        .count = 1,
#endif
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_reset_activation(emulator);
    dfc_host_set_free_observer(NULL, NULL);
    for(size_t index = 0; index < audit.count; index++) {
        munit_assert_true(audit.regions[index].observed);
        munit_assert_true(audit.regions[index].zeroed);
    }
    munit_assert_memory_equal(
        sizeof(emulator->rnd_b), emulator->rnd_b, ((uint8_t[sizeof(emulator->rnd_b)]){0}));
    munit_assert_memory_equal(
        sizeof(*emulator->tx_buffer),
        emulator->tx_buffer,
        ((uint8_t[sizeof(*emulator->tx_buffer)]){0}));
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static void
    assert_native_exchange_bytebuf_reused_and_wiped(size_t response_capacity, int expected_status) {
    DfcCredential credential = {0};
    munit_assert_true(dfc_credential_clear(&credential));
    credential.card.generation = DfcGenerationEv3;
    credential.card.storage = 4096;
    memcpy(credential.uid, "\x04\x11\x22\x33\x44\x55\x66", DFC_DESFIRE_UID_LEN);
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    DfcVirtualPiccSession* picc = dfc_virtual_picc_session_alloc(&credential);
    munit_assert_not_null(picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(picc, &activation), ==, DfcVirtualPiccStatusOk);

    const uint8_t command[] = {0xFF};
    uint8_t response[16] = {0};
    size_t response_len = 0;
    ByteBufFreeAudit audit = {.zeroed = false};
    dfc_host_set_free_observer(observe_freed_bytebuf, &audit);
    DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_exchange(
        picc, command, sizeof(command), response, response_capacity, &response_len);
    dfc_host_set_free_observer(NULL, NULL);

    munit_assert_int(status, ==, expected_status);
    munit_assert_size(audit.count, ==, 0);
    munit_assert_memory_equal(
        sizeof(*picc->emulator->tx_buffer),
        picc->emulator->tx_buffer,
        ((uint8_t[sizeof(*picc->emulator->tx_buffer)]){0}));
    dfc_virtual_picc_session_free(picc);
}

static MunitResult
    test_native_exchange_wipes_bytebuf_on_all_exits(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    assert_native_exchange_bytebuf_reused_and_wiped(16, DfcVirtualPiccStatusOk);
    assert_native_exchange_bytebuf_reused_and_wiped(0, DfcVirtualPiccStatusBufferTooSmall);
    return MUNIT_OK;
}

static MunitResult test_d40_block_cleanup_paths(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    uint8_t encrypted[16] = {0};
    uint8_t plain[sizeof(encrypted)];
    memset(plain, 0xA5, sizeof(plain));
    munit_assert_true(dfc_emulator_d40_receive_plain(
        AuditDesKey, sizeof(AuditDesKey), encrypted, sizeof(encrypted), plain));

    memset(plain, 0xA5, sizeof(plain));
    munit_assert_false(
        dfc_emulator_d40_receive_plain(AuditDesKey, 7, encrypted, sizeof(encrypted), plain));
    munit_assert_memory_equal(sizeof(plain), plain, ((uint8_t[sizeof(plain)]){0}));

    ReaderAuthAudit audit;
    reader_auth_audit_open(
        &audit,
        DfcGenerationEv3,
        DFC_KEY_TYPE_DES_2K3DES,
        DFC_CMD_AUTHENTICATE_LEGACY,
        AuditDesKey,
        sizeof(AuditDesKey));
    DfcReaderExchange exchange;
    munit_assert_int(
        reader_auth_audit_native(
            &audit, &exchange, DFC_CMD_AUTHENTICATE_LEGACY, AuditDesKey, sizeof(AuditDesKey)),
        ==,
        DfcReaderOk);
    const uint8_t wrong_key[sizeof(AuditDesKey)] = {0xFF};
    munit_assert_int(
        reader_auth_audit_native(
            &audit, &exchange, DFC_CMD_AUTHENTICATE_LEGACY, wrong_key, sizeof(wrong_key)),
        !=,
        DfcReaderOk);
    reader_auth_audit_close(&audit);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/reader-auth-transients-and-family-commit",
     test_reader_authentication_transients_and_family_commit,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/owned-storage-wiped-before-free",
     test_emulator_owned_storage_wiped_before_free,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/session-reset-wipes-command-chain",
     test_session_reset_wipes_command_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/activation-reset-wipes-storage",
     test_activation_reset_wipes_retained_and_released_storage,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/native-exchange-wipes-bytebuf",
     test_native_exchange_wipes_bytebuf_on_all_exits,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/d40-block-cleanup-paths",
     test_d40_block_cleanup_paths,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_teardown",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
