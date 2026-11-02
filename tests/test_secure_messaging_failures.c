#include "munit.h"

#include "dfc_crypto_internal.h"
#include "dfc_emulator_i.h"
#include "dfc_ev2_crypto.h"
#include "dfc_port.h"
#include "dfc_reader.h"
#include "dfc_secure_messaging.h"
#include "dfc_virtual_picc.h"

#include <stdlib.h>
#include <string.h>

static size_t aes_block_call;
static size_t aes_operation;
static size_t des_block_call;
static size_t des_operation;
static size_t fail_at;
static size_t fail_aes_operation;
static size_t fail_des_operation;
static size_t aes_cbc_operation;
static size_t fail_aes_cbc_operation;
static bool fail_cbc;
static bool fail_secure_messaging_alloc;
static bool fail_random_fill;
static bool random_failure_retryable;
static size_t random_fill_calls;

bool dfc_crypto_aes_block_init(DfcCryptoAesBlock* block, const uint8_t* key, size_t key_len) {
    if(!block || !key || key_len != 16) return false;
    memset(block, 0, sizeof(*block));
    block->initialized = true;
    aes_block_call = 0;
    aes_operation++;
    return true;
}

bool dfc_crypto_aes_block_encrypt(
    DfcCryptoAesBlock* block,
    const uint8_t input[16],
    uint8_t output[16]) {
    if(!block || !block->initialized || !input || !output) return false;
    aes_block_call++;
    if(aes_block_call == fail_at &&
       (fail_aes_operation == 0 || aes_operation == fail_aes_operation))
        return false;
    for(size_t i = 0; i < 16; i++)
        output[i] = input[i] ^ (uint8_t)(0x31 + aes_block_call);
    return true;
}

void dfc_crypto_aes_block_clear(DfcCryptoAesBlock* block) {
    if(block) memset(block, 0, sizeof(*block));
}

bool dfc_crypto_des_block_init(
    DfcCryptoDesBlock* block,
    bool encrypt,
    const uint8_t* key,
    size_t key_len) {
    if(!block || !key || (key_len != 8 && key_len != 16 && key_len != 24)) return false;
    memset(block, 0, sizeof(*block));
    block->key_len = key_len;
    block->encrypt = encrypt;
    block->initialized = true;
    des_block_call = 0;
    des_operation++;
    return true;
}

bool dfc_crypto_des_block_crypt(
    DfcCryptoDesBlock* block,
    const uint8_t input[8],
    uint8_t output[8]) {
    if(!block || !block->initialized || !input || !output) return false;
    des_block_call++;
    if(des_block_call == fail_at &&
       (fail_des_operation == 0 || des_operation == fail_des_operation))
        return false;
    for(size_t i = 0; i < 8; i++)
        output[i] = input[i] ^ (uint8_t)(0x51 + des_block_call);
    return true;
}

void dfc_crypto_des_block_clear(DfcCryptoDesBlock* block) {
    if(block) memset(block, 0, sizeof(*block));
}

static bool emulate_cbc(
    bool encrypt,
    uint8_t* iv,
    size_t block_size,
    const uint8_t* input,
    uint8_t* output,
    size_t length) {
    if(fail_cbc) {
        memset(iv, 0xDD, block_size);
        if(length) memset(output, 0xCC, length);
        return false;
    }
    uint8_t last_input[16] = {0};
    if(!encrypt && length) memcpy(last_input, input + length - block_size, block_size);
    for(size_t i = 0; i < length; i++)
        output[i] = input[i] ^ 0xA7;
    if(length) {
        if(encrypt) {
            memcpy(iv, output + length - block_size, block_size);
        } else {
            memcpy(iv, last_input, block_size);
        }
    }
    memset(last_input, 0, sizeof(last_input));
    return true;
}

bool dfc_crypto_aes_cbc(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    uint8_t iv[16],
    const uint8_t* input,
    uint8_t* output,
    size_t length) {
    (void)key;
    if(key_len != 16 || length % 16 != 0) return false;
    aes_cbc_operation++;
    if(fail_aes_cbc_operation != 0 && aes_cbc_operation == fail_aes_cbc_operation) {
        memset(iv, 0xDD, 16);
        if(length) memset(output, 0xCC, length);
        return false;
    }
    return emulate_cbc(encrypt, iv, 16, input, output, length);
}

bool dfc_crypto_des_cbc(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    uint8_t iv[8],
    const uint8_t* input,
    uint8_t* output,
    size_t length) {
    (void)key;
    if((key_len != 8 && key_len != 16 && key_len != 24) || length % 8 != 0) return false;
    return emulate_cbc(encrypt, iv, 8, input, output, length);
}

bool dfc_crypto_des_ecb(
    bool encrypt,
    const uint8_t* key,
    size_t key_len,
    const uint8_t input[8],
    uint8_t output[8]) {
    DfcCryptoDesBlock block;
    if(!dfc_crypto_des_block_init(&block, encrypt, key, key_len)) return false;
    bool ok = dfc_crypto_des_block_crypt(&block, input, output);
    dfc_crypto_des_block_clear(&block);
    return ok;
}

bool dfc_random_fill(uint8_t* data, size_t length) {
    random_fill_calls++;
    if(fail_random_fill) {
        random_failure_retryable = true;
        return false;
    }
    for(size_t i = 0; i < length; i++)
        data[i] = (uint8_t)(0x20 + i);
    return true;
}

void dfc_random_operation_begin(void) {
    random_failure_retryable = false;
}

bool dfc_random_failure_is_retryable(void) {
    return random_failure_retryable;
}

void dfc_port_notify(void* context, DfcEvent event) {
    (void)context;
    (void)event;
}

void* dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    if(tag == DfcAllocSecureMessaging && fail_secure_messaging_alloc) return NULL;
    return calloc(1, size);
}

void dfc_platform_free(void* ptr) {
    free(ptr);
}

static void init_session(DfcSecureMessaging* sm, uint8_t cipher, size_t key_len) {
    memset(sm, 0, sizeof(*sm));
    sm->cipher = cipher;
    sm->session_key_len = key_len;
    for(size_t i = 0; i < sizeof(sm->session_key); i++)
        sm->session_key[i] = (uint8_t)(0x10 + i);
    for(size_t i = 0; i < sizeof(sm->iv); i++)
        sm->iv[i] = (uint8_t)(0x80 + i);
}

static void assert_zeroed(const uint8_t* data, size_t length) {
    uint8_t zero[DFC_SM_MAX_CRYPTO_SIZE] = {0};
    munit_assert_size(length, <=, sizeof(zero));
    munit_assert_memory_equal(length, data, zero);
}

static void assert_filled(const uint8_t* data, size_t length, uint8_t value) {
    for(size_t i = 0; i < length; i++)
        munit_assert_uint8(data[i], ==, value);
}

static void assert_reader_prepare_failure(
    uint8_t auth_mode,
    size_t key_len,
    uint8_t comm_mode,
    bool cbc_failure,
    const DfcCommand* command) {
    DfcReaderSession session;
    dfc_reader_session_init(&session);
    session.auth_mode = auth_mode;
    init_session(&session.sm, auth_mode, key_len);
    session.sm.pcd = true;
    if(auth_mode == DFC_READER_AUTH_EV2) {
        memset(session.ev2_encryption_key, 0x21, sizeof(session.ev2_encryption_key));
        memset(session.ev2_mac_key, 0x32, sizeof(session.ev2_mac_key));
        memset(
            session.ev2_transaction_identifier, 0x43, sizeof(session.ev2_transaction_identifier));
    }
    DfcReaderSession before = session;
    DfcReaderExchange exchange;
    DfcReaderOptions options = {.comm_mode = comm_mode};
    fail_at = cbc_failure ? 0 : 1;
    fail_cbc = cbc_failure;
    munit_assert_int(
        dfc_reader_exchange_begin(&exchange, &session, DfcReaderFramingIso7816, command, &options),
        ==,
        DfcReaderIntegrityError);
    assert_zeroed(exchange.frame, sizeof(exchange.frame));
    munit_assert_size(exchange.frame_len, ==, 0);
    munit_assert_memory_equal(sizeof(before), &session, &before);
    fail_at = 0;
    fail_cbc = false;
}

static MunitResult test_reader_prepare_crypto_failures_are_terminal(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCommand mac_command = {.ins = DFC_CMD_GET_KEY_SETTINGS, .data_len = 0};
    assert_reader_prepare_failure(DFC_CMD_AUTHENTICATE_AES, 16, DFC_COMM_MAC, false, &mac_command);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_reader_prepare_failure(
            DFC_CMD_AUTHENTICATE_ISO, key_len, DFC_COMM_MAC, false, &mac_command);
    }

    uint8_t payload[9] = {0};
    DfcCommand write_command;
    munit_assert_int(
        dfc_command_write_data(&write_command, 1, 0, payload, sizeof(payload)), ==, DfcCommandOk);
    assert_reader_prepare_failure(
        DFC_CMD_AUTHENTICATE_LEGACY, 8, DFC_COMM_MAC, false, &write_command);
    assert_reader_prepare_failure(
        DFC_CMD_AUTHENTICATE_LEGACY, 16, DFC_COMM_MAC, false, &write_command);
    assert_reader_prepare_failure(
        DFC_CMD_AUTHENTICATE_LEGACY, 8, DFC_COMM_ENCIPHERED, false, &write_command);
    assert_reader_prepare_failure(
        DFC_CMD_AUTHENTICATE_LEGACY, 16, DFC_COMM_ENCIPHERED, false, &write_command);
    assert_reader_prepare_failure(
        DFC_CMD_AUTHENTICATE_AES, 16, DFC_COMM_ENCIPHERED, true, &write_command);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_reader_prepare_failure(
            DFC_CMD_AUTHENTICATE_ISO, key_len, DFC_COMM_ENCIPHERED, true, &write_command);
    }

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    assert_reader_prepare_failure(
        DFC_READER_AUTH_EV2, 16, DFC_COMM_ENCIPHERED, true, &write_command);
    assert_reader_prepare_failure(DFC_READER_AUTH_EV2, 16, DFC_COMM_MAC, false, &mac_command);
#endif
    return MUNIT_OK;
}

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* picc;
    DfcReaderSession reader;
} FaultLink;

static void assert_iso_auth_pending_cleared(const DfcEmulator* emulator) {
    munit_assert_uint8(emulator->iso_auth_phase, ==, 0);
    munit_assert_uint8(emulator->iso_auth_challenge_len, ==, 0);
    munit_assert_uint8(emulator->iso_auth_key_no, ==, 0);
    munit_assert_uint8(emulator->iso_auth_cipher, ==, 0);
    munit_assert_uint8(emulator->iso_auth_reference, ==, 0);
    munit_assert_size(emulator->iso_auth_key_len, ==, 0);
    assert_zeroed(
        emulator->pending_authentication.iso_auth_card_first,
        sizeof(emulator->pending_authentication.iso_auth_card_first));
    assert_zeroed(
        emulator->pending_authentication.iso_auth_host_first,
        sizeof(emulator->pending_authentication.iso_auth_host_first));
    assert_zeroed(
        emulator->pending_authentication.iso_auth_external_iv,
        sizeof(emulator->pending_authentication.iso_auth_external_iv));
    assert_zeroed(
        emulator->pending_authentication.iso_auth_key,
        sizeof(emulator->pending_authentication.iso_auth_key));
}

static DfcReaderStatus run_exchange(FaultLink* link, DfcReaderExchange* exchange) {
    uint8_t command[DFC_COMMAND_MAX_APDU];
    size_t command_len = 0;
    uint8_t response[DFC_READER_MAX_RESPONSE + 16];
    size_t response_len = 0;
    const uint8_t* answer = NULL;
    DfcReaderStatus status;
    while((status = dfc_reader_step(
               exchange, answer, response_len, command, sizeof(command), &command_len)) ==
          DfcReaderPending) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link->picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        answer = response;
    }
    return status;
}

static void send_plain(FaultLink* link, const DfcCommand* command) {
    DfcReaderExchange exchange;
    DfcReaderOptions options = {0};
    munit_assert_int(
        dfc_reader_exchange_begin(
            &exchange, &link->reader, DfcReaderFramingIso7816, command, &options),
        ==,
        DfcReaderOk);
    munit_assert_int(run_exchange(link, &exchange), ==, DfcReaderOk);
}

static void
    fault_link_authenticate(FaultLink* link, uint8_t command, const uint8_t* key, size_t key_len) {
    const uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0xA0};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_begin(
            &exchange,
            &link->reader,
            DfcReaderFramingIso7816,
            command,
            0,
            key,
            key_len,
            random_a,
            dfc_reader_challenge_length(command, key_len)),
        ==,
        DfcReaderOk);
    munit_assert_int(run_exchange(link, &exchange), ==, DfcReaderOk);
}

static void fault_link_open(
    FaultLink* link,
    uint8_t auth_command,
    uint8_t key_type,
    const uint8_t* key,
    size_t key_len) {
    memset(link, 0, sizeof(*link));
    const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0x04, 1, 2, 3, 4, 5, 6};
    memcpy(link->credential.uid, uid, sizeof(uid));
    link->credential.uid_len = sizeof(uid);
    link->credential.card.generation = DfcGenerationEv1;
    const uint8_t aid[3] = {1, 2, 3};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &link->credential, aid, 0x0F, key_type | 1);
    munit_assert_not_null(app);
    app->auth_command = auth_command;
    app->has_auth_commands = true;
    app->auth_commands = dfc_credential_default_auth_commands(key_type | 1, DfcGenerationEv1);
    munit_assert_size(app->key_len, ==, key_len);
    memcpy(dfc_credential_key(&link->credential, app, 0), key, key_len);

    DfcFile* file = dfc_credential_create_file(&link->credential, 0, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->comm_settings = DFC_COMM_MAC;
    file->access_rights = 0;
    munit_assert_true(dfc_file_resize(&link->credential, file, 32));
    uint8_t* file_data = dfc_file_data(&link->credential, file);
    for(size_t i = 0; i < 32; i++)
        file_data[i] = (uint8_t)(0x60 + i);

    link->picc = dfc_virtual_picc_session_alloc(&link->credential);
    munit_assert_not_null(link->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(link->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&link->reader);

    DfcCommand select;
    const uint8_t human_aid[3] = {3, 2, 1};
    munit_assert_int(dfc_command_select_application(&select, human_aid, NULL), ==, DfcCommandOk);
    send_plain(link, &select);
    fault_link_authenticate(link, auth_command, key, key_len);
}

static void fault_link_close(FaultLink* link) {
    dfc_virtual_picc_session_free(link->picc);
}

static size_t fault_emulator_command(
    DfcEmulator* emulator,
    const uint8_t* command,
    size_t command_len,
    uint8_t response[64],
    bool expected_handled) {
    DfcByteBuf* tx = dfc_bytebuf_alloc(64);
    munit_assert_not_null(tx);
    munit_assert_int(
        dfc_emulator_handle_command(emulator, command, command_len, tx, NULL),
        ==,
        expected_handled);
    size_t response_len = dfc_bytebuf_get_size_bytes(tx);
    memcpy(response, dfc_bytebuf_get_data(tx), response_len);
    dfc_bytebuf_free(tx);
    return response_len;
}

static DfcEmulator* get_value_fault_emulator(
    DfcCredential* credential,
    uint8_t cipher,
    size_t key_len,
    uint8_t comm_mode) {
    munit_assert_true(dfc_credential_clear(credential));
    credential->card.generation = DfcGenerationEv1;
    const uint8_t aid[3] = {1, 2, 3};
    uint8_t key_type = cipher == DFC_CMD_AUTHENTICATE_AES ? DFC_KEY_TYPE_AES :
                       key_len == DFC_MAX_KEY_LEN         ? DFC_KEY_TYPE_3K3DES :
                                                            DFC_KEY_TYPE_DES_2K3DES;
    munit_assert_not_null(
        dfc_credential_create_application_desfire_order(credential, aid, 0x0F, key_type | 1));
    DfcFile* file = dfc_credential_create_file(credential, 0, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_VALUE;
    file->comm_settings = comm_mode;
    file->access_rights = 0;
    file->state.value.current = 0x12345678;

    DfcEmulator* emulator = dfc_emulator_alloc(credential);
    munit_assert_not_null(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;
    emulator->auth_cipher = cipher;
    emulator->auth_key_no = 0;
    uint8_t key[DFC_MAX_KEY_LEN];
    memset(key, 0x42, sizeof(key));
    emulator->secure_messaging = dfc_secure_messaging_alloc(cipher, key, key_len, NULL);
    dfc_secure_wipe(key, sizeof(key));
    munit_assert_not_null(emulator->secure_messaging);
    return emulator;
}

static void assert_get_value_protection_failure(
    uint8_t cipher,
    size_t key_len,
    uint8_t comm_mode,
    size_t failed_block,
    size_t failed_operation,
    bool cbc_failure) {
    DfcCredential credential;
    DfcEmulator* emulator = get_value_fault_emulator(&credential, cipher, key_len, comm_mode);
    const uint8_t command[] = {DFC_CMD_GET_VALUE, 1};
    uint8_t response[64];

    aes_block_call = 0;
    aes_operation = 0;
    des_block_call = 0;
    des_operation = 0;
    fail_at = failed_block;
    fail_aes_operation = cipher == DFC_CMD_AUTHENTICATE_AES ? failed_operation : 0;
    fail_des_operation = cipher == DFC_CMD_AUTHENTICATE_AES ? 0 : failed_operation;
    fail_cbc = cbc_failure;
    size_t response_len =
        fault_emulator_command(emulator, command, sizeof(command), response, true);

    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_false(dfc_emulator_native_authentication_active(emulator));
    munit_assert_memory_equal(
        sizeof(*emulator->secure_messaging),
        emulator->secure_messaging,
        ((uint8_t[sizeof(*emulator->secure_messaging)]){0}));
    munit_assert_uint8(emulator->auth_cipher, ==, 0);
    munit_assert_uint8(emulator->auth_key_no, ==, 0);

    fail_at = 0;
    fail_aes_operation = 0;
    fail_des_operation = 0;
    fail_cbc = false;
    dfc_emulator_free(emulator);
}

static MunitResult
    test_get_value_protection_failures_fail_closed(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;

    for(size_t key_len = 8; key_len <= 16; key_len += 8) {
        assert_get_value_protection_failure(
            DFC_CMD_AUTHENTICATE_LEGACY, key_len, DFC_COMM_MAC, 1, 1, false);
        assert_get_value_protection_failure(
            DFC_CMD_AUTHENTICATE_LEGACY, key_len, DFC_COMM_ENCIPHERED, 1, 1, false);
    }

    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        for(size_t block = 1; block <= 2; block++) {
            assert_get_value_protection_failure(
                DFC_CMD_AUTHENTICATE_ISO, key_len, DFC_COMM_MAC, block, 2, false);
        }
        assert_get_value_protection_failure(
            DFC_CMD_AUTHENTICATE_ISO, key_len, DFC_COMM_ENCIPHERED, 0, 0, true);
    }

    for(size_t block = 1; block <= 2; block++) {
        assert_get_value_protection_failure(
            DFC_CMD_AUTHENTICATE_AES, 16, DFC_COMM_MAC, block, 2, false);
    }
    assert_get_value_protection_failure(
        DFC_CMD_AUTHENTICATE_AES, 16, DFC_COMM_ENCIPHERED, 0, 0, true);
    return MUNIT_OK;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING

static void assert_ev2_active_capabilities(
    const DfcEmulator* emulator,
    const uint8_t card[DFC_EV2_CAPABILITY_LENGTH],
    const uint8_t reader[DFC_EV2_CAPABILITY_LENGTH]) {
    munit_assert_memory_equal(DFC_EV2_CAPABILITY_LENGTH, emulator->ev2_card_capabilities, card);
    munit_assert_memory_equal(
        DFC_EV2_CAPABILITY_LENGTH, emulator->ev2_reader_capabilities, reader);
}

static void assert_ev2_session_cleared(const DfcEmulator* emulator) {
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

static void assert_ev2_pending_cleared(const DfcEmulator* emulator) {
    const uint8_t zero[DFC_AES_KEY_LENGTH] = {0};
    munit_assert_false(emulator->ev2_authentication_pending);
    munit_assert_false(emulator->ev2_authentication_non_first);
    munit_assert_uint8(emulator->ev2_pending_authenticated_key_no, ==, 0);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.static_key),
        emulator->pending_authentication.ev2.static_key,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.random_b),
        emulator->pending_authentication.ev2.random_b,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.transaction_identifier),
        emulator->pending_authentication.ev2.transaction_identifier,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.card_capabilities),
        emulator->pending_authentication.ev2.card_capabilities,
        zero);
    munit_assert_memory_equal(
        sizeof(emulator->pending_authentication.ev2.reader_capabilities),
        emulator->pending_authentication.ev2.reader_capabilities,
        zero);
}

static void prepare_ev2_continuation(
    const DfcEmulator* emulator,
    uint8_t continuation[1 + DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH]) {
    continuation[0] = DFC_CMD_ADDITIONAL_FRAME;
    for(size_t i = 0; i < DFC_EV2_RANDOM_LENGTH; i++)
        continuation[1 + i] = (uint8_t)(0x70 + i) ^ 0xA7;
    for(size_t i = 0; i < DFC_EV2_RANDOM_LENGTH; i++) {
        continuation[1 + DFC_EV2_RANDOM_LENGTH + i] =
            emulator->pending_authentication.ev2.random_b[(i + 1) % DFC_EV2_RANDOM_LENGTH] ^ 0xA7;
    }
}

static MunitResult test_ev2_crypto_failures_clear_accepted_session(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    munit_assert_true(dfc_credential_clear(&credential));
    credential.card.generation = DfcGenerationEv3;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    credential.picc_has_ev2_capabilities = true;
    const uint8_t new_card[DFC_EV2_CAPABILITY_LENGTH] = {13, 14, 15, 16, 17, 18};
    const uint8_t new_reader[DFC_EV2_CAPABILITY_LENGTH] = {19, 20, 21, 22, 23, 24};
    memcpy(credential.picc_ev2_capabilities, new_card, sizeof(new_card));
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, DFC_AES_KEY_LENGTH));
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    const uint8_t active_card[DFC_EV2_CAPABILITY_LENGTH] = {1, 2, 3, 4, 5, 6};
    const uint8_t active_reader[DFC_EV2_CAPABILITY_LENGTH] = {7, 8, 9, 10, 11, 12};
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 7;
    memcpy(emulator->ev2_card_capabilities, active_card, sizeof(active_card));
    memcpy(emulator->ev2_reader_capabilities, active_reader, sizeof(active_reader));

    const uint8_t begin[] = {
        DFC_CMD_AUTHENTICATE_EV2_FIRST, 0, sizeof(new_reader), 19, 20, 21, 22, 23, 24};
    uint8_t response[64];
    fail_random_fill = true;
    munit_assert_size(
        fault_emulator_command(emulator, begin, sizeof(begin), response, true), ==, 1);
    fail_random_fill = false;
    munit_assert_uint8(response[0], ==, DFC_STATUS_MEMORY_ERROR);
    assert_ev2_active_capabilities(emulator, active_card, active_reader);
    assert_ev2_pending_cleared(emulator);

    fail_cbc = true;
    munit_assert_size(
        fault_emulator_command(emulator, begin, sizeof(begin), response, true), ==, 1);
    fail_cbc = false;
    munit_assert_uint8(response[0], ==, DFC_STATUS_MEMORY_ERROR);
    assert_ev2_session_cleared(emulator);
    assert_ev2_pending_cleared(emulator);

    for(size_t failure_kind = 0; failure_kind < 3; failure_kind++) {
        aes_operation = 0;
        aes_cbc_operation = 0;
        fail_at = 0;
        fail_aes_operation = 0;
        fail_aes_cbc_operation = 0;
        munit_assert_size(
            fault_emulator_command(emulator, begin, sizeof(begin), response, true),
            ==,
            1 + DFC_EV2_RANDOM_LENGTH);
        uint8_t continuation[1 + DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH];
        prepare_ev2_continuation(emulator, continuation);
        aes_operation = 0;
        aes_cbc_operation = 0;
        if(failure_kind == 0) {
            fail_aes_cbc_operation = 1;
        } else if(failure_kind == 1) {
            fail_aes_operation = 1;
            fail_at = 1;
        } else {
            fail_aes_cbc_operation = 2;
        }
        munit_assert_size(
            fault_emulator_command(emulator, continuation, sizeof(continuation), response, true),
            ==,
            1);
        munit_assert_uint8(response[0], ==, DFC_STATUS_MEMORY_ERROR);
        assert_ev2_session_cleared(emulator);
        assert_ev2_pending_cleared(emulator);
    }

    fail_at = 0;
    fail_aes_operation = 0;
    fail_aes_cbc_operation = 0;
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}
#endif

static MunitResult test_native_reauthentication_reuses_retired_session_allocation(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fail_at = 0;
    fail_cbc = false;
    fail_secure_messaging_alloc = false;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));

    DfcSecureMessaging* old_session = link.picc->emulator->secure_messaging;
    munit_assert_not_null(old_session);
    old_session->iv[0] = 0x5A;
    DfcSecureMessaging old_value = *old_session;

    const uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0xA0};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_begin(
            &exchange,
            &link.reader,
            DfcReaderFramingIso7816,
            DFC_CMD_AUTHENTICATE_AES,
            0,
            key,
            sizeof(key),
            random_a,
            DFC_AES_KEY_LENGTH),
        ==,
        DfcReaderOk);
    fail_secure_messaging_alloc = true;
    munit_assert_int(run_exchange(&link, &exchange), ==, DfcReaderOk);
    fail_secure_messaging_alloc = false;

    munit_assert_ptr_equal(link.picc->emulator->secure_messaging, old_session);
    munit_assert_memory_not_equal(sizeof(old_value), old_session, &old_value);
    munit_assert_true(dfc_emulator_native_authentication_active(link.picc->emulator));
    munit_assert_uint8(link.picc->emulator->auth_key_no, ==, 0);
    munit_assert_true(dfc_reader_session_is_authenticated(&link.reader));
    fault_link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_native_initial_authentication_allocation_failure(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fail_at = 0;
    fail_cbc = false;
    fail_secure_messaging_alloc = false;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    dfc_secure_messaging_free(link.picc->emulator->secure_messaging);
    link.picc->emulator->secure_messaging = NULL;
    link.picc->emulator->auth_cipher = 0;
    link.picc->emulator->auth_key_no = 0;

    const uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0xA0};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_begin(
            &exchange,
            &link.reader,
            DfcReaderFramingIso7816,
            DFC_CMD_AUTHENTICATE_AES,
            0,
            key,
            sizeof(key),
            random_a,
            DFC_AES_KEY_LENGTH),
        ==,
        DfcReaderOk);
    fail_secure_messaging_alloc = true;
    munit_assert_int(run_exchange(&link, &exchange), ==, DfcReaderCardError);
    fail_secure_messaging_alloc = false;

    munit_assert_null(link.picc->emulator->secure_messaging);
    munit_assert_uint8(link.picc->emulator->auth_cipher, ==, 0);
    munit_assert_uint8(link.picc->emulator->auth_key_no, ==, 0);
    munit_assert_false(link.picc->emulator->awaiting_step2);
    munit_assert_uint8(link.picc->emulator->pending_auth_cipher, ==, 0);
    munit_assert_uint8(link.picc->emulator->pending_auth_key_no, ==, 0);
    fault_link_close(&link);
    return MUNIT_OK;
}

#if DFC_ENABLE_TRANSACTION_MAC && DFC_ENABLE_EV2_SECURE_MESSAGING
static void
    assert_transaction_mac_failure_aborts(bool return_transaction_mac, size_t failed_cmac_block) {
    static DfcCredential credential;
    munit_assert_true(dfc_credential_clear(&credential));
    credential.card.generation = DfcGenerationEv3;
    const uint8_t aid[3] = {1, 2, 3};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);

    DfcFile* value = dfc_credential_create_file(&credential, 0, 1);
    munit_assert_not_null(value);
    value->type = DFC_FILE_TYPE_VALUE;
    value->state.value.current = 100;
    value->state.value.pending = true;
    value->state.value.pending_delta = 7;

    DfcFile* transaction = dfc_credential_create_file(&credential, 0, 2);
    munit_assert_not_null(transaction);
    transaction->type = DFC_FILE_TYPE_TRANSACTION_MAC;
    transaction->access_rights = 0xEFFE;
    transaction->state.transaction_mac.counter = 9;
    memset(
        transaction->state.transaction_mac.key,
        0x42,
        sizeof(transaction->state.transaction_mac.key));
    munit_assert_true(dfc_file_resize(&credential, transaction, DFC_TRANSACTION_MAC_FILE_LENGTH));

    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;
    memset(&emulator->transaction_mac, 0x70, sizeof(emulator->transaction_mac));
    emulator->transaction_mac.initialized = true;
    emulator->transaction_mac.has_pending = true;
    uint8_t command[2] = {DFC_CMD_COMMIT_TRANSACTION, DFC_TRANSACTION_COMMIT_RETURN_MAC_OPTION};
    size_t command_len = return_transaction_mac ? sizeof(command) : 1;
    uint8_t response[64];
    aes_operation = 0;
    fail_at = failed_cmac_block;
    fail_aes_operation = 1;
    size_t response_len = fault_emulator_command(emulator, command, command_len, response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_int(value->state.value.current, ==, 100);
    munit_assert_false(value->state.value.pending);
    munit_assert_int(value->state.value.pending_delta, ==, 0);
    munit_assert_uint32(transaction->state.transaction_mac.counter, ==, 9);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));

    aes_operation = 0;
    fail_at = 0;
    fail_aes_operation = 0;
    response_len = fault_emulator_command(emulator, command, command_len, response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_NO_CHANGES);
    munit_assert_int(value->state.value.current, ==, 100);
    munit_assert_false(value->state.value.pending);
    munit_assert_int(value->state.value.pending_delta, ==, 0);
    munit_assert_uint32(transaction->state.transaction_mac.counter, ==, 9);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));
    dfc_emulator_free(emulator);
}

static MunitResult
    test_transaction_mac_failures_abort(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    for(size_t return_mac = 0; return_mac < 2; return_mac++) {
        for(size_t block = 1; block <= 2; block++)
            assert_transaction_mac_failure_aborts(return_mac != 0, block);
    }
    fail_at = 0;
    fail_aes_operation = 0;
    return MUNIT_OK;
}

static DfcEmulator*
    transaction_test_emulator(DfcCredential* credential, DfcFile** value, DfcFile** transaction) {
    munit_assert_true(dfc_credential_clear(credential));
    credential->card.generation = DfcGenerationEv3;
    credential->uid_len = DFC_DESFIRE_UID_LEN;
    const uint8_t aid[3] = {1, 2, 3};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1));
    *value = dfc_credential_create_file(credential, 0, 1);
    munit_assert_not_null(*value);
    (*value)->type = DFC_FILE_TYPE_VALUE;
    (*value)->access_rights = 0xEEEE;
    (*value)->state.value.lower_limit = -1000;
    (*value)->state.value.upper_limit = 1000;
    (*value)->state.value.current = 100;
    *transaction = dfc_credential_create_file(credential, 0, 2);
    munit_assert_not_null(*transaction);
    (*transaction)->type = DFC_FILE_TYPE_TRANSACTION_MAC;
    (*transaction)->access_rights = 0xEFFE;
    memset(
        (*transaction)->state.transaction_mac.key,
        0x42,
        sizeof((*transaction)->state.transaction_mac.key));
    munit_assert_true(dfc_file_resize(credential, *transaction, DFC_TRANSACTION_MAC_FILE_LENGTH));
    DfcFile* data = dfc_credential_create_file(credential, 0, 3);
    munit_assert_not_null(data);
    data->type = DFC_FILE_TYPE_BACKUP_DATA;
    data->access_rights = 0xEEEE;
    munit_assert_true(dfc_file_resize(credential, data, 32));
    memset(dfc_file_data(credential, data), 0x31, 32);
    DfcFile* record = dfc_credential_create_file(credential, 0, 4);
    munit_assert_not_null(record);
    record->type = DFC_FILE_TYPE_LINEAR_RECORD;
    record->access_rights = 0xEEEE;
    record->state.record.size = 32;
    record->state.record.max_records = 2;
    record->state.record.count = 1;
    munit_assert_true(dfc_file_resize(credential, record, 64));
    memset(dfc_file_data(credential, record), 0x42, 64);
    DfcEmulator* emulator = dfc_emulator_alloc(credential);
    munit_assert_not_null(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;
    return emulator;
}

static void enable_transaction_reader_id_authentication(DfcEmulator* emulator, DfcFile* file) {
    file->access_rights = 0xEFEE;
    emulator->ev2_session_active = true;
    emulator->ev2_authenticated_key_no = 0;
}

static MunitResult
    test_transaction_transcript_bounds(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    DfcFile* value;
    DfcFile* transaction;
    uint8_t response[64];
    const uint8_t credit[] = {DFC_CMD_CREDIT, 1, 7, 0, 0, 0};
    DfcEmulator* emulator = transaction_test_emulator(&credential, &value, &transaction);
    for(size_t operation = 0; operation < 10; operation++) {
        size_t response_len =
            fault_emulator_command(emulator, credit, sizeof(credit), response, true);
        munit_assert_size(response_len, ==, 1);
        munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    }
    munit_assert_true(value->state.value.pending);
    munit_assert_int(value->state.value.pending_delta, ==, 70);
    munit_assert_true(emulator->transaction_mac.has_pending);
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static void reset_aes_fault(size_t block) {
    aes_operation = 0;
    fail_at = block;
    fail_aes_operation = 1;
}

static void clear_aes_fault(void) {
    aes_operation = 0;
    fail_at = 0;
    fail_aes_operation = 0;
}

static uint8_t
    run_transaction_command(DfcEmulator* emulator, const uint8_t* command, size_t command_length) {
    uint8_t response[64];
    size_t response_length =
        fault_emulator_command(emulator, command, command_length, response, true);
    munit_assert_size(response_length, ==, 1);
    return response[0];
}

static MunitResult
    test_transaction_streaming_failures_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    DfcFile* value;
    DfcFile* transaction;
    const uint8_t credit[] = {DFC_CMD_CREDIT, 1, 7, 0, 0, 0};

    DfcEmulator* emulator = transaction_test_emulator(&credential, &value, &transaction);
    DfcTransactionMacAccumulator empty = emulator->transaction_mac;
    reset_aes_fault(1);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(empty), &emulator->transaction_mac, &empty);
    munit_assert_false(value->state.value.pending);
    munit_assert_int32(value->state.value.current, ==, 100);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);

    DfcTransactionMacAccumulator prior = emulator->transaction_mac;
    int32_t prior_pending_value = value->state.value.pending_value;
    int32_t prior_pending_delta = value->state.value.pending_delta;
    reset_aes_fault(1);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_true(value->state.value.pending);
    munit_assert_int32(value->state.value.pending_value, ==, prior_pending_value);
    munit_assert_int32(value->state.value.pending_delta, ==, prior_pending_delta);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    prior = emulator->transaction_mac;
    prior_pending_value = value->state.value.pending_value;
    DfcFile* data = dfc_credential_find_file_in_app(&credential, 0, 3);
    uint8_t original_data[32];
    memcpy(original_data, dfc_file_data_const(&credential, data), sizeof(original_data));
    uint8_t write[8 + sizeof(original_data)] = {DFC_CMD_WRITE_DATA, 3, 0, 0, 0, 32, 0, 0};
    memset(write + 8, 0xA5, sizeof(original_data));
    reset_aes_fault(2);
    munit_assert_uint8(
        run_transaction_command(emulator, write, sizeof(write)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_memory_equal(
        sizeof(original_data), dfc_file_data_const(&credential, data), original_data);
    munit_assert_false(data->transaction_pending);
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_int32(value->state.value.pending_value, ==, prior_pending_value);
    clear_aes_fault();
    munit_assert_uint8(run_transaction_command(emulator, write, sizeof(write)), ==, DFC_STATUS_OK);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    prior = emulator->transaction_mac;
    prior_pending_value = value->state.value.pending_value;
    DfcFile* record = dfc_credential_find_file_in_app(&credential, 0, 4);
    uint8_t original_record[32];
    memcpy(original_record, dfc_file_data_const(&credential, record), sizeof(original_record));
    uint8_t update[11 + sizeof(original_record)] = {
        DFC_CMD_UPDATE_RECORD, 4, 0, 0, 0, 0, 0, 0, 32, 0, 0};
    memset(update + 11, 0xB6, sizeof(original_record));
    reset_aes_fault(2);
    munit_assert_uint8(
        run_transaction_command(emulator, update, sizeof(update)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_memory_equal(
        sizeof(original_record), dfc_file_data_const(&credential, record), original_record);
    munit_assert_false(record->transaction_pending);
    munit_assert_false(emulator->transaction_snapshot_active);
    munit_assert_int32(value->state.value.pending_value, ==, prior_pending_value);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, update, sizeof(update)), ==, DFC_STATUS_OK);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    prior = emulator->transaction_mac;
    record = dfc_credential_find_file_in_app(&credential, 0, 4);
    memcpy(original_record, dfc_file_data_const(&credential, record), sizeof(original_record));
    uint8_t write_record[8 + sizeof(original_record)] = {
        DFC_CMD_WRITE_RECORD, 4, 0, 0, 0, 32, 0, 0};
    memset(write_record + 8, 0xC7, sizeof(original_record));
    reset_aes_fault(2);
    munit_assert_uint8(
        run_transaction_command(emulator, write_record, sizeof(write_record)),
        ==,
        DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_memory_equal(
        sizeof(original_record), dfc_file_data_const(&credential, record), original_record);
    munit_assert_uint32(record->state.record.count, ==, 1);
    munit_assert_false(record->transaction_pending);
    munit_assert_false(emulator->transaction_snapshot_active);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, write_record, sizeof(write_record)), ==, DFC_STATUS_OK);

    prior = emulator->transaction_mac;
    uint8_t written_record[64];
    memcpy(written_record, dfc_file_data_const(&credential, record), sizeof(written_record));
    reset_aes_fault(2);
    munit_assert_uint8(
        run_transaction_command(emulator, write_record, sizeof(write_record)),
        ==,
        DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_memory_equal(
        sizeof(written_record), dfc_file_data_const(&credential, record), written_record);
    munit_assert_true(record->transaction_pending);
    munit_assert_true(emulator->transaction_snapshot_active);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, write_record, sizeof(write_record)), ==, DFC_STATUS_OK);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    record = dfc_credential_find_file_in_app(&credential, 0, 4);
    prior = emulator->transaction_mac;
    memcpy(original_record, dfc_file_data_const(&credential, record), sizeof(original_record));
    const uint8_t clear_record[] = {DFC_CMD_CLEAR_RECORD_FILE, 4};
    reset_aes_fault(1);
    munit_assert_uint8(
        run_transaction_command(emulator, clear_record, sizeof(clear_record)),
        ==,
        DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(prior), &emulator->transaction_mac, &prior);
    munit_assert_memory_equal(
        sizeof(original_record), dfc_file_data_const(&credential, record), original_record);
    munit_assert_uint32(record->state.record.count, ==, 1);
    munit_assert_false(record->transaction_pending);
    munit_assert_false(emulator->transaction_snapshot_active);
    clear_aes_fault();
    munit_assert_uint8(
        run_transaction_command(emulator, clear_record, sizeof(clear_record)), ==, DFC_STATUS_OK);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t initial_iv[DFC_AES_KEY_LENGTH];
    memset(initial_iv, 0x5C, sizeof(initial_iv));
    emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), initial_iv);
    munit_assert_not_null(emulator->secure_messaging);
    emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    emulator->auth_key_no = 0;
    DfcSecureMessaging* reader = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), initial_iv);
    munit_assert_not_null(reader);
    munit_assert_true(dfc_secure_messaging_update_ev1_command(
        reader, credit[0], credit + 1, sizeof(credit) - 1));
    uint8_t response_mac[DFC_WIRE_MAC_LENGTH];
    munit_assert_true(dfc_secure_messaging_generate_ev1_response_mac(
        reader, DFC_STATUS_OK, NULL, 0, response_mac));

    reset_aes_fault(1);
    fail_aes_operation = 2;
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_memory_equal(sizeof(initial_iv), emulator->secure_messaging->iv, initial_iv);
    munit_assert_true(dfc_emulator_native_authentication_active(emulator));
    clear_aes_fault();
    uint8_t authenticated_response[64];
    size_t authenticated_response_length =
        fault_emulator_command(emulator, credit, sizeof(credit), authenticated_response, true);
    munit_assert_size(authenticated_response_length, ==, 1 + DFC_WIRE_MAC_LENGTH);
    munit_assert_uint8(authenticated_response[0], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(sizeof(reader->iv), emulator->secure_messaging->iv, reader->iv);
    munit_assert_memory_equal(sizeof(response_mac), authenticated_response + 1, response_mac);
    munit_assert_true(dfc_emulator_native_authentication_active(emulator));
    dfc_secure_messaging_free(reader);
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    emulator->secure_messaging = dfc_secure_messaging_alloc(
        DFC_CMD_AUTHENTICATE_AES, session_key, sizeof(session_key), initial_iv);
    munit_assert_not_null(emulator->secure_messaging);
    emulator->auth_cipher = DFC_CMD_AUTHENTICATE_AES;
    emulator->auth_key_no = 0;
    credential.uid_len = 0;
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_false(value->state.value.pending);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));
    munit_assert_false(dfc_emulator_native_authentication_active(emulator));
    dfc_emulator_free(emulator);

    emulator = transaction_test_emulator(&credential, &value, &transaction);
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_OK);
    transaction->state.transaction_mac.counter = UINT32_MAX;
    munit_assert_uint8(
        run_transaction_command(emulator, credit, sizeof(credit)), ==, DFC_STATUS_BOUNDARY_ERROR);
    munit_assert_false(value->state.value.pending);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult
    test_transaction_counter_does_not_wrap(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    DfcFile* value;
    DfcFile* transaction;
    DfcEmulator* emulator = transaction_test_emulator(&credential, &value, &transaction);
    transaction->state.transaction_mac.counter = UINT32_MAX;
    value->state.value.pending = true;
    value->state.value.pending_delta = 7;
    memset(&emulator->transaction_mac, 0x33, sizeof(emulator->transaction_mac));
    emulator->transaction_mac.initialized = true;
    emulator->transaction_mac.has_pending = true;
    uint8_t response[64];
    const uint8_t commit[] = {DFC_CMD_COMMIT_TRANSACTION};
    size_t response_len = fault_emulator_command(emulator, commit, sizeof(commit), response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_uint32(transaction->state.transaction_mac.counter, ==, UINT32_MAX);
    munit_assert_false(value->state.value.pending);
    munit_assert_int(value->state.value.pending_delta, ==, 0);
    munit_assert_int(value->state.value.current, ==, 100);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));

    const uint8_t commit_reader_id[1 + DFC_TRANSACTION_READER_ID_LENGTH] = {
        DFC_CMD_COMMIT_READER_ID};
    transaction->access_rights = 0xEFEE;
    response_len = fault_emulator_command(
        emulator, commit_reader_id, sizeof(commit_reader_id), response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    munit_assert_uint32(transaction->state.transaction_mac.counter, ==, UINT32_MAX);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult
    test_commit_reader_id_is_transactional(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    DfcFile* value;
    DfcFile* transaction;
    DfcEmulator* emulator = transaction_test_emulator(&credential, &value, &transaction);
    enable_transaction_reader_id_authentication(emulator, transaction);
    (void)value;
    uint8_t original[DFC_TRANSACTION_READER_ID_LENGTH];
    uint8_t first[DFC_TRANSACTION_READER_ID_LENGTH];
    uint8_t second[DFC_TRANSACTION_READER_ID_LENGTH];
    for(size_t i = 0; i < sizeof(original); i++) {
        original[i] = (uint8_t)(0x10 + i);
        first[i] = (uint8_t)(0x40 + i);
        second[i] = (uint8_t)(0x70 + i);
    }
    memcpy(transaction->state.transaction_mac.previous_reader_id, original, sizeof(original));

    uint8_t command[1 + DFC_TRANSACTION_READER_ID_LENGTH] = {DFC_CMD_COMMIT_READER_ID};
    memcpy(command + 1, first, sizeof(first));
    uint8_t response[64];
    size_t response_len =
        fault_emulator_command(emulator, command, sizeof(command), response, true);
    munit_assert_size(response_len, ==, 1 + DFC_TRANSACTION_READER_ID_LENGTH);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    for(size_t i = 0; i < sizeof(original); i++)
        munit_assert_uint8(response[i + 1], ==, (uint8_t)(original[i] ^ 0xA7));
    munit_assert_memory_equal(
        sizeof(original), transaction->state.transaction_mac.previous_reader_id, original);

    const uint8_t abort[] = {DFC_CMD_ABORT_TRANSACTION};
    response_len = fault_emulator_command(emulator, abort, sizeof(abort), response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(
        sizeof(original), transaction->state.transaction_mac.previous_reader_id, original);
    assert_zeroed((const uint8_t*)&emulator->transaction_mac, sizeof(emulator->transaction_mac));

    response_len = fault_emulator_command(emulator, command, sizeof(command), response, true);
    munit_assert_size(response_len, ==, 1 + DFC_TRANSACTION_READER_ID_LENGTH);
    const uint8_t commit[] = {DFC_CMD_COMMIT_TRANSACTION};
    response_len = fault_emulator_command(emulator, commit, sizeof(commit), response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(
        sizeof(first), transaction->state.transaction_mac.previous_reader_id, first);

    memcpy(command + 1, second, sizeof(second));
    response_len = fault_emulator_command(emulator, command, sizeof(command), response, true);
    munit_assert_size(response_len, ==, 1 + DFC_TRANSACTION_READER_ID_LENGTH);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    for(size_t i = 0; i < sizeof(first); i++)
        munit_assert_uint8(response[i + 1], ==, (uint8_t)(first[i] ^ 0xA7));
    munit_assert_memory_equal(
        sizeof(first), transaction->state.transaction_mac.previous_reader_id, first);

    response_len = fault_emulator_command(emulator, commit, sizeof(commit), response, true);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_OK);
    munit_assert_memory_equal(
        sizeof(second), transaction->state.transaction_mac.previous_reader_id, second);
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

#if DFC_ENABLE_PROXIMITY_CHECK
static void assert_proximity_terminal_wipe(size_t failed_mac_operation) {
    static DfcCredential credential;
    munit_assert_true(dfc_credential_clear(&credential));
    credential.card.generation = DfcGenerationEv3;
    credential.picc_has_proximity_key = true;
    for(size_t i = 0; i < sizeof(credential.picc_proximity_key); i++)
        credential.picc_proximity_key[i] = (uint8_t)(0x20 + i);
    credential.picc_proximity_published_response_time = 0x0102;
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);

    uint8_t response[64];
    const uint8_t prepare[] = {DFC_CMD_PREPARE_PROXIMITY_CHECK};
    size_t response_len =
        fault_emulator_command(emulator, prepare, sizeof(prepare), response, true);
    munit_assert_size(response_len, ==, 4);
    munit_assert_uint8(response[0], ==, DFC_STATUS_SPECIAL_SUCCESS);
    uint8_t published[4] = {0};
    memcpy(published, response + 1, response_len - 1);

    uint8_t round[2 + DFC_PROXIMITY_RANDOM_LENGTH] = {
        DFC_CMD_PROXIMITY_CHECK, DFC_PROXIMITY_RANDOM_LENGTH};
    for(size_t i = 0; i < DFC_PROXIMITY_RANDOM_LENGTH; i++)
        round[i + 2] = (uint8_t)(0x90 + i);
    response_len = fault_emulator_command(emulator, round, sizeof(round), response, true);
    munit_assert_size(response_len, ==, 1 + DFC_PROXIMITY_RANDOM_LENGTH);
    munit_assert_uint8(response[0], ==, DFC_STATUS_SPECIAL_SUCCESS);

    uint8_t transcript[DFC_PROXIMITY_TRANSCRIPT_MAX] = {0};
    memcpy(transcript, response + 1, DFC_PROXIMITY_RANDOM_LENGTH);
    memcpy(transcript + DFC_PROXIMITY_RANDOM_LENGTH, round + 2, DFC_PROXIMITY_RANDOM_LENGTH);
    uint8_t verify[1 + DFC_WIRE_MAC_LENGTH] = {DFC_CMD_VERIFY_PROXIMITY_CHECK};
    munit_assert_true(dfc_reader_proximity_check_mac(
        credential.picc_proximity_key,
        false,
        published,
        3,
        transcript,
        2 * DFC_PROXIMITY_RANDOM_LENGTH,
        verify + 1));

    aes_operation = 0;
    fail_at = failed_mac_operation ? 1 : 0;
    fail_aes_operation = failed_mac_operation;
    response_len = fault_emulator_command(emulator, verify, sizeof(verify), response, true);
    if(failed_mac_operation) {
        munit_assert_size(response_len, ==, 1);
        munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
        munit_assert_false(emulator->proximity_verified);
    } else {
        munit_assert_size(response_len, ==, 1 + DFC_WIRE_MAC_LENGTH);
        munit_assert_uint8(response[0], ==, DFC_STATUS_SPECIAL_SUCCESS);
        munit_assert_true(emulator->proximity_verified);
    }
    munit_assert_false(emulator->proximity_active);
    munit_assert_size(emulator->proximity_offset, ==, 0);
    munit_assert_size(emulator->proximity_transcript_len, ==, 0);
    assert_zeroed(emulator->proximity_random, sizeof(emulator->proximity_random));
    assert_zeroed(emulator->proximity_transcript, sizeof(emulator->proximity_transcript));
    fail_at = 0;
    fail_aes_operation = 0;
    dfc_emulator_free(emulator);
}

static MunitResult
    test_proximity_terminal_paths_wipe_state(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_proximity_terminal_wipe(1);
    assert_proximity_terminal_wipe(2);
    assert_proximity_terminal_wipe(0);
    return MUNIT_OK;
}
#endif

static MunitResult
    test_transaction_file_creation_rolls_back(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static DfcCredential credential;
    static DfcCredential before;
    munit_assert_true(dfc_credential_clear(&credential));
    credential.card.generation = DfcGenerationEv3;
    const uint8_t aid[3] = {1, 2, 3};
    munit_assert_not_null(dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1));
    size_t remaining = DFC_FILE_POOL_SIZE - 1;
    uint8_t file_number = 1;
    while(remaining) {
        size_t chunk = remaining > DFC_MAX_FILE_DATA ? DFC_MAX_FILE_DATA : remaining;
        DfcFile* filler = dfc_credential_create_file(&credential, 0, file_number++);
        munit_assert_not_null(filler);
        filler->type = DFC_FILE_TYPE_STANDARD_DATA;
        munit_assert_true(dfc_file_resize(&credential, filler, chunk));
        remaining -= chunk;
    }
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    emulator->selected_app_index = 0;
    before = credential;
    DfcCommand encoded_command;
    DfcCommandTransactionMacFile transaction_file = {
        .file_no = file_number,
        .comm_settings = DFC_COMM_PLAIN,
        .access_rights = 0xEFEE,
        .key_type = DFC_TRANSACTION_MAC_KEY_TYPE_AES,
    };
    munit_assert_int(
        dfc_command_create_transaction_mac_file(&encoded_command, &transaction_file),
        ==,
        DfcCommandOk);
    uint8_t command[DFC_COMMAND_MAX_APDU];
    size_t command_len = 0;
    munit_assert_int(
        dfc_command_to_frame(&encoded_command, command, sizeof(command), &command_len),
        ==,
        DfcCommandOk);
    uint8_t response[64];
    for(size_t attempt = 0; attempt < 2; attempt++) {
        size_t response_len =
            fault_emulator_command(emulator, command, command_len, response, true);
        munit_assert_size(response_len, ==, 1);
        munit_assert_uint8(response[0], ==, DFC_STATUS_OUT_OF_EEPROM);
        munit_assert_memory_equal(sizeof(before), &before, &credential);
    }
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}
#endif

static MunitResult test_iso7816_reauthentication_reuses_retired_session_allocation(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    const uint8_t random_first[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    const uint8_t random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    fail_at = 0;
    fail_cbc = false;
    fail_secure_messaging_alloc = false;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    link.credential.apps[0].auth_commands |= DFC_AUTH_COMMAND_ISO7816;

    DfcSecureMessaging* old_session = link.picc->emulator->secure_messaging;
    munit_assert_not_null(old_session);
    old_session->iv[0] = 0x5A;
    DfcSecureMessaging old_value = *old_session;

    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            &exchange,
            &link.reader,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            key,
            sizeof(key),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            random_first,
            random_second,
            sizeof(random_first)),
        ==,
        DfcReaderOk);

    uint8_t command[DFC_COMMAND_MAX_APDU];
    size_t command_len = 0;
    uint8_t response[DFC_READER_MAX_RESPONSE + 16];
    size_t response_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, command, sizeof(command), &command_len),
        ==,
        DfcReaderPending);
    for(size_t step = 0; step < 2; step++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_int(
            dfc_reader_step(
                &exchange, response, response_len, command, sizeof(command), &command_len),
            ==,
            DfcReaderPending);
    }

    fail_secure_messaging_alloc = true;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    fail_secure_messaging_alloc = false;
    munit_assert_size(
        response_len, ==, DFC_ISO7816_AUTH_CHALLENGE_LONG * 2 + DFC_ISO7816_STATUS_WORD_LENGTH);
    assert_iso_auth_pending_cleared(link.picc->emulator);

    munit_assert_ptr_equal(link.picc->emulator->secure_messaging, old_session);
    munit_assert_memory_not_equal(sizeof(old_value), old_session, &old_value);
    munit_assert_true(dfc_emulator_native_authentication_active(link.picc->emulator));
    munit_assert_uint8(link.picc->emulator->auth_key_no, ==, 0);
    fault_link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_iso7816_initial_authentication_allocation_failure(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    const uint8_t random_first[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xA1};
    const uint8_t random_second[DFC_ISO7816_AUTH_CHALLENGE_LONG] = {0xB2};
    fail_at = 0;
    fail_cbc = false;
    fail_secure_messaging_alloc = false;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    link.credential.apps[0].auth_commands |= DFC_AUTH_COMMAND_ISO7816;
    dfc_secure_messaging_free(link.picc->emulator->secure_messaging);
    link.picc->emulator->secure_messaging = NULL;
    link.picc->emulator->auth_cipher = 0;
    link.picc->emulator->auth_key_no = 0;

    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_iso7816_begin(
            &exchange,
            &link.reader,
            DFC_ISO7816_AUTH_APP_REFERENCE,
            key,
            sizeof(key),
            DFC_ISO7816_AUTH_ALGORITHM_AES,
            random_first,
            random_second,
            sizeof(random_first)),
        ==,
        DfcReaderOk);

    uint8_t command[DFC_COMMAND_MAX_APDU];
    size_t command_len = 0;
    uint8_t response[DFC_READER_MAX_RESPONSE + 16];
    size_t response_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, command, sizeof(command), &command_len),
        ==,
        DfcReaderPending);
    for(size_t step = 0; step < 2; step++) {
        munit_assert_int(
            dfc_virtual_picc_iso_dep_exchange(
                link.picc, command, command_len, response, sizeof(response), &response_len),
            ==,
            DfcVirtualPiccStatusOk);
        munit_assert_int(
            dfc_reader_step(
                &exchange, response, response_len, command, sizeof(command), &command_len),
            ==,
            DfcReaderPending);
    }

    fail_secure_messaging_alloc = true;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusProtocolError);
    fail_secure_messaging_alloc = false;
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint8(link.picc->emulator->iso_auth_phase, ==, 2);
    munit_assert_null(link.picc->emulator->secure_messaging);
    munit_assert_uint8(link.picc->emulator->auth_cipher, ==, 0);
    munit_assert_uint8(link.picc->emulator->auth_key_no, ==, 0);
    fault_link_close(&link);
    return MUNIT_OK;
}

static void assert_cmac_generation_failure(
    uint8_t cipher,
    size_t key_len,
    size_t plain_len,
    size_t positions) {
    uint8_t plain[32] = {0};
    for(size_t position = 1; position <= positions; position++) {
        fail_at = position;
        DfcSecureMessaging sm;
        init_session(&sm, cipher, key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        uint8_t output[64];
        memset(output, 0xA5, sizeof(output));

        size_t result = dfc_secure_messaging_generate_ev1_response(
            &sm, DFC_STATUS_OK, plain, plain_len, output, sizeof(output));

        munit_assert_size(result, ==, 0);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
        assert_filled(output, sizeof(output), 0xA5);
    }
}

static MunitResult
    test_cmac_failure_positions_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    fail_cbc = false;
    assert_cmac_generation_failure(DFC_CMD_AUTHENTICATE_AES, 16, 31, 3);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_cmac_generation_failure(DFC_CMD_AUTHENTICATE_ISO, key_len, 15, 3);
    }
    return MUNIT_OK;
}

static MunitResult
    test_ev2_session_key_derivation_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    const uint8_t random_a[DFC_EV2_RANDOM_LENGTH] = {0x22};
    const uint8_t random_b[DFC_EV2_RANDOM_LENGTH] = {0x33};
    for(size_t operation = 1; operation <= 2; operation++) {
        uint8_t encryption_key[DFC_AES_KEY_LENGTH];
        uint8_t mac_key[DFC_AES_KEY_LENGTH];
        memset(encryption_key, 0xA5, sizeof(encryption_key));
        memset(mac_key, 0xA5, sizeof(mac_key));
        aes_operation = 0;
        fail_aes_operation = operation;
        fail_at = 1;
        munit_assert_false(
            dfc_ev2_derive_session_keys(key, random_a, random_b, encryption_key, mac_key));
        assert_zeroed(encryption_key, sizeof(encryption_key));
        assert_zeroed(mac_key, sizeof(mac_key));
    }
    fail_aes_operation = 0;
    fail_at = 0;
    return MUNIT_OK;
}

static void assert_d40_mac_wrap_failure(size_t key_len) {
    uint8_t plain[32] = {0};
    for(fail_at = 1; fail_at <= sizeof(plain) / DFC_SM_LEGACY_BLOCK_SIZE; fail_at++) {
        DfcSecureMessaging sm;
        init_session(&sm, DFC_CMD_AUTHENTICATE_LEGACY, key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        uint8_t output[64];
        memset(output, 0xA5, sizeof(output));

        size_t result = dfc_secure_messaging_wrap_d40_command_mac(
            &sm, plain, sizeof(plain), output, sizeof(output));

        munit_assert_size(result, ==, 0);
        munit_assert_size(des_block_call, ==, fail_at);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
        assert_filled(output, sizeof(output), 0xA5);
    }
}

static MunitResult
    test_mac_wrap_propagates_every_failure(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    fail_cbc = false;
    assert_d40_mac_wrap_failure(8);
    assert_d40_mac_wrap_failure(16);
    return MUNIT_OK;
}

static void
    assert_failed_cmac_rejects_zero_tag(uint8_t cipher, size_t key_len, size_t command_len) {
    uint8_t command[32] = {0};
    for(fail_at = 1; fail_at <= 3; fail_at++) {
        DfcSecureMessaging sm;
        init_session(&sm, cipher, key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        munit_assert_size(
            dfc_secure_messaging_verify_ev1_transmitted_command_mac_full(&sm, command, command_len),
            ==,
            SIZE_MAX);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
    }
}

static MunitResult
    test_failed_cmac_cannot_authenticate_zero_tag(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    fail_cbc = false;
    assert_failed_cmac_rejects_zero_tag(DFC_CMD_AUTHENTICATE_AES, 16, 32);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_failed_cmac_rejects_zero_tag(DFC_CMD_AUTHENTICATE_ISO, key_len, 24);
    }
    return MUNIT_OK;
}

static void assert_update_failure(uint8_t cipher, size_t key_len, size_t command_len) {
    uint8_t command[32] = {DFC_CMD_GET_FILE_SETTINGS};
    for(fail_at = 1; fail_at <= 3; fail_at++) {
        DfcSecureMessaging sm;
        init_session(&sm, cipher, key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        munit_assert_false(
            dfc_secure_messaging_update_ev1_command_full(&sm, command, command_len));
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
    }
}

static MunitResult
    test_ev1_update_propagates_every_failure(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    fail_cbc = false;
    assert_update_failure(DFC_CMD_AUTHENTICATE_AES, 16, 32);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_update_failure(DFC_CMD_AUTHENTICATE_ISO, key_len, 16);
    }
    return MUNIT_OK;
}

static MunitResult
    test_invalid_key_widths_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const struct {
        uint8_t cipher;
        size_t key_len;
    } cases[] = {
        {DFC_CMD_AUTHENTICATE_AES, 8},
        {DFC_CMD_AUTHENTICATE_ISO, 7},
        {DFC_CMD_AUTHENTICATE_ISO, 17},
    };
    uint8_t plain[16] = {0};
    fail_at = 0;
    fail_cbc = false;
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        DfcSecureMessaging sm;
        init_session(&sm, cases[i].cipher, cases[i].key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        uint8_t output[32];
        memset(output, 0xA5, sizeof(output));
        munit_assert_size(
            dfc_secure_messaging_generate_ev1_response(
                &sm, DFC_STATUS_OK, plain, sizeof(plain), output, sizeof(output)),
            ==,
            0);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
        assert_filled(output, sizeof(output), 0xA5);
    }
    return MUNIT_OK;
}

static MunitResult
    test_in_place_failure_restores_spare_byte(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcSecureMessaging sm;
    init_session(&sm, DFC_CMD_AUTHENTICATE_AES, 16);
    uint8_t before_iv[sizeof(sm.iv)];
    memcpy(before_iv, sm.iv, sizeof(before_iv));
    uint8_t buffer[40];
    memset(buffer, 0xA5, sizeof(buffer));
    fail_at = 1;
    fail_cbc = false;
    munit_assert_size(
        dfc_secure_messaging_generate_ev1_response_in_place(
            &sm, DFC_STATUS_OK, buffer, 31, sizeof(buffer)),
        ==,
        0);
    munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
    assert_filled(buffer, sizeof(buffer), 0xA5);
    return MUNIT_OK;
}

static void assert_cbc_failure_is_atomic(uint8_t cipher, size_t key_len) {
    uint8_t plain[17] = {1, 2, 3, 4, 5, 6, 7};
    size_t wrapped_len = cipher == DFC_CMD_AUTHENTICATE_AES ? 32 : 24;
    size_t failure_positions = cipher == DFC_CMD_AUTHENTICATE_LEGACY ? 3 : 1;
    for(size_t position = 1; position <= failure_positions; position++) {
        uint8_t wrapped[32];
        DfcSecureMessaging sm;
        init_session(&sm, cipher, key_len);
        uint8_t before_iv[sizeof(sm.iv)];
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        memset(wrapped, 0xA5, sizeof(wrapped));

        fail_at = cipher == DFC_CMD_AUTHENTICATE_LEGACY ? position : 0;
        fail_cbc = cipher != DFC_CMD_AUTHENTICATE_LEGACY;
        munit_assert_size(
            dfc_secure_messaging_wrap(
                &sm, DFC_COMM_ENCIPHERED, NULL, 0, plain, sizeof(plain), wrapped, sizeof(wrapped)),
            ==,
            0);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
        assert_zeroed(wrapped, wrapped_len);

        init_session(&sm, cipher, key_len);
        memcpy(before_iv, sm.iv, sizeof(before_iv));
        uint8_t output[32];
        memset(output, 0xA5, sizeof(output));
        uint8_t ciphertext[32] = {0};
        fail_at = cipher == DFC_CMD_AUTHENTICATE_LEGACY ? position : 0;
        fail_cbc = cipher != DFC_CMD_AUTHENTICATE_LEGACY;
        size_t output_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_unwrap(
            &sm,
            DFC_COMM_ENCIPHERED,
            DFC_STATUS_OK,
            ciphertext,
            wrapped_len,
            output,
            sizeof(output),
            &output_len));
        munit_assert_size(output_len, ==, 0);
        munit_assert_memory_equal(sizeof(before_iv), sm.iv, before_iv);
        assert_zeroed(output, wrapped_len);
    }
}

static MunitResult test_cbc_failures_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_cbc_failure_is_atomic(DFC_CMD_AUTHENTICATE_AES, 16);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_cbc_failure_is_atomic(DFC_CMD_AUTHENTICATE_ISO, key_len);
    }
    assert_cbc_failure_is_atomic(DFC_CMD_AUTHENTICATE_LEGACY, 8);
    assert_cbc_failure_is_atomic(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    fail_cbc = false;
    fail_at = 0;
    return MUNIT_OK;
}

static void
    assert_response_mac_failure_and_retry(uint8_t cipher, size_t key_len, size_t positions) {
    const uint8_t plain[32] = {1, 2, 3, 4, 5, 6, 7, 8};
    DfcSecureMessaging writer;
    init_session(&writer, cipher, key_len);
    fail_at = 0;
    fail_cbc = false;
    uint8_t wrapped[48];
    size_t wrapped_len = dfc_secure_messaging_generate_d40_response_mac(
        &writer, plain, sizeof(plain), wrapped, sizeof(wrapped));
    munit_assert_size(wrapped_len, >, sizeof(plain));

    for(size_t position = 1; position <= positions; position++) {
        fail_at = position;
        DfcSecureMessaging reader;
        init_session(&reader, cipher, key_len);
        reader.pcd = true;
        uint8_t before_iv[sizeof(reader.iv)];
        memcpy(before_iv, reader.iv, sizeof(before_iv));
        uint8_t output[sizeof(plain)];
        memset(output, 0xA5, sizeof(output));

        size_t output_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_unwrap_d40_response_mac(
            &reader, wrapped, wrapped_len, output, sizeof(output), &output_len));
        munit_assert_size(output_len, ==, 0);
        munit_assert_memory_equal(sizeof(before_iv), reader.iv, before_iv);
        assert_filled(output, sizeof(output), 0xA5);

        fail_at = 0;
        munit_assert_true(dfc_secure_messaging_unwrap_d40_response_mac(
            &reader, wrapped, wrapped_len, output, sizeof(output), &output_len));
        munit_assert_size(output_len, ==, sizeof(plain));
        munit_assert_memory_equal(sizeof(plain), output, plain);
    }
}

static MunitResult
    test_response_mac_failures_allow_retry(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_response_mac_failure_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 8, 4);
    assert_response_mac_failure_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 16, 4);
    return MUNIT_OK;
}

static void assert_response_mac_call_chain_retry(
    uint8_t auth_command,
    uint8_t key_type,
    const uint8_t* key,
    size_t key_len,
    size_t final_position) {
    static FaultLink link;
    fail_at = 0;
    fail_cbc = false;
    fault_link_open(&link, auth_command, key_type, key, key_len);

    DfcCommand command;
    munit_assert_int(dfc_command_read_data(&command, 1, 0, 32), ==, DfcCommandOk);
    DfcReaderOptions options = {.comm_mode = DFC_COMM_MAC};
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_exchange_begin(
            &exchange, &link.reader, DfcReaderFramingIso7816, &command, &options),
        ==,
        DfcReaderOk);

    uint8_t request[DFC_COMMAND_MAX_APDU];
    size_t request_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, request, sizeof(request), &request_len),
        ==,
        DfcReaderPending);

    fail_at = final_position;
    uint8_t response[64];
    memset(response, 0xA5, sizeof(response));
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, request, request_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 2);
    munit_assert_memory_equal(
        response_len, response, ((uint8_t[]){0x91, DFC_STATUS_INTEGRITY_ERROR}));
    for(size_t i = 0; i < sizeof(link.picc->emulator->pending_chain); i++)
        munit_assert_uint8(link.picc->emulator->pending_chain[i], ==, 0);

    size_t ignored = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, response, response_len, request, sizeof(request), &ignored),
        ==,
        DfcReaderCardError);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.reader));

    fail_at = 0;
    fault_link_authenticate(&link, auth_command, key, key_len);
    munit_assert_int(
        dfc_reader_exchange_begin(
            &exchange, &link.reader, DfcReaderFramingIso7816, &command, &options),
        ==,
        DfcReaderOk);
    munit_assert_int(run_exchange(&link, &exchange), ==, DfcReaderOk);
    size_t data_len = 0;
    const uint8_t* data = dfc_reader_result_data(&exchange, &data_len);
    munit_assert_size(data_len, ==, 32);
    for(size_t i = 0; i < data_len; i++)
        munit_assert_uint8(data[i], ==, (uint8_t)(0x60 + i));
    fault_link_close(&link);
}

static MunitResult
    test_response_mac_call_chains_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    const uint8_t aes_key[16] = {0x11};
    const uint8_t des_key[16] = {0x22};
    assert_response_mac_call_chain_retry(
        DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, aes_key, sizeof(aes_key), 4);
    assert_response_mac_call_chain_retry(
        DFC_CMD_AUTHENTICATE_ISO, DFC_KEY_TYPE_DES_2K3DES, des_key, sizeof(des_key), 6);
    return MUNIT_OK;
}

static void
    assert_command_mac_failure_and_retry(uint8_t cipher, size_t key_len, size_t positions) {
    uint8_t plain[32];
    for(size_t i = 0; i < sizeof(plain); i++)
        plain[i] = (uint8_t)i;
    DfcSecureMessaging writer;
    init_session(&writer, cipher, key_len);
    writer.pcd = true;
    fail_at = 0;
    fail_cbc = false;
    uint8_t wrapped[48];
    size_t wrapped_len = dfc_secure_messaging_wrap_d40_command_mac(
        &writer, plain, sizeof(plain), wrapped, sizeof(wrapped));
    munit_assert_size(wrapped_len, >, sizeof(plain));

    for(size_t position = 1; position <= positions; position++) {
        fail_at = position;
        DfcSecureMessaging card;
        init_session(&card, cipher, key_len);
        uint8_t before_iv[sizeof(card.iv)];
        memcpy(before_iv, card.iv, sizeof(before_iv));
        uint8_t output[sizeof(plain)];
        memset(output, 0xA5, sizeof(output));

        size_t output_len = SIZE_MAX;
        munit_assert_false(dfc_secure_messaging_verify_d40_command_mac(
            &card, wrapped, wrapped_len, output, sizeof(output), &output_len));
        munit_assert_size(output_len, ==, 0);
        munit_assert_memory_equal(sizeof(before_iv), card.iv, before_iv);
        assert_filled(output, sizeof(output), 0xA5);

        fail_at = 0;
        munit_assert_true(dfc_secure_messaging_verify_d40_command_mac(
            &card, wrapped, wrapped_len, output, sizeof(output), &output_len));
        munit_assert_size(output_len, ==, sizeof(plain));
        munit_assert_memory_equal(sizeof(plain), output, plain);
    }
}

static MunitResult
    test_command_mac_failures_allow_retry(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_command_mac_failure_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 8, 4);
    assert_command_mac_failure_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 16, 4);
    return MUNIT_OK;
}

static void assert_crc_rejection_and_retry(uint8_t cipher, size_t key_len) {
    const uint8_t header[] = {DFC_CMD_WRITE_DATA, 1, 0, 0, 0, 17, 0, 0};
    uint8_t plain[17];
    for(size_t i = 0; i < sizeof(plain); i++)
        plain[i] = (uint8_t)(0x40 + i);
    DfcSecureMessaging writer;
    init_session(&writer, cipher, key_len);
    writer.pcd = true;
    fail_at = 0;
    fail_cbc = false;
    uint8_t wrapped[32];
    size_t wrapped_len = dfc_secure_messaging_wrap(
        &writer,
        DFC_COMM_ENCIPHERED,
        header,
        sizeof(header),
        plain,
        sizeof(plain),
        wrapped,
        sizeof(wrapped));
    munit_assert_size(wrapped_len, >, sizeof(plain));

    uint8_t tampered[sizeof(wrapped)];
    memcpy(tampered, wrapped, wrapped_len);
    tampered[0] ^= 1;
    DfcSecureMessaging card;
    init_session(&card, cipher, key_len);
    uint8_t before_iv[sizeof(card.iv)];
    memcpy(before_iv, card.iv, sizeof(before_iv));
    uint8_t output[sizeof(wrapped)];
    memset(output, 0xA5, sizeof(output));
    munit_assert_size(
        dfc_secure_messaging_verify_command(
            &card,
            DFC_COMM_ENCIPHERED,
            header,
            sizeof(header),
            tampered,
            wrapped_len,
            output,
            sizeof(output)),
        ==,
        0);
    munit_assert_memory_equal(sizeof(before_iv), card.iv, before_iv);
    assert_zeroed(output, wrapped_len);

    munit_assert_size(
        dfc_secure_messaging_verify_command(
            &card,
            DFC_COMM_ENCIPHERED,
            header,
            sizeof(header),
            wrapped,
            wrapped_len,
            output,
            sizeof(output)),
        ==,
        sizeof(plain));
    munit_assert_memory_equal(sizeof(plain), output, plain);
}

static MunitResult test_crc_failures_allow_retry(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_crc_rejection_and_retry(DFC_CMD_AUTHENTICATE_AES, 16);
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        assert_crc_rejection_and_retry(DFC_CMD_AUTHENTICATE_ISO, key_len);
    }
    assert_crc_rejection_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 8);
    assert_crc_rejection_and_retry(DFC_CMD_AUTHENTICATE_LEGACY, 16);
    return MUNIT_OK;
}

#if DFC_ENABLE_SDM
static DfcFile* configure_sdm_fault_file(FaultLink* link) {
    DfcFile* file = dfc_credential_find_file_in_app(&link->credential, 0, 1);
    munit_assert_not_null(file);
    munit_assert_true(dfc_file_resize(&link->credential, file, 128));
    uint8_t* file_data = dfc_file_data(&link->credential, file);
    munit_assert_not_null(file_data);
    for(size_t i = 0; i < file->data_len; i++)
        file_data[i] = (uint8_t)(0x30 + (i % 10));
    dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
    dfc_file_sdm_flag_set(file, DfcSdmFlagPiccDataOffset, true);
    file->state.data.sdm.picc_data_offset = 0;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacInputOffset, true);
    file->state.data.sdm.mac_input_offset = 64;
    dfc_file_sdm_flag_set(file, DfcSdmFlagMacOffset, true);
    file->state.data.sdm.mac_offset = 80;
    dfc_file_sdm_flag_set(file, DfcSdmFlagEncryptedFile, true);
    file->state.data.sdm.encrypted_file_offset = 96;
    file->state.data.sdm.encrypted_file_length = 32;
    file->state.data.sdm.access_rights = 0;
    file->state.data.sdm_read_counter = 41;
    return file;
}

static void assert_sdm_fault_rolls_back_and_retries(size_t cmac_operation, size_t cbc_operation) {
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fail_at = 0;
    fail_cbc = false;
    fail_aes_operation = 0;
    fail_aes_cbc_operation = 0;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    DfcFile* file = configure_sdm_fault_file(&link);
    DfcEmulator* emulator = link.picc->emulator;
    uint8_t before_cache[DFC_SDM_READ_CACHE_SIZE];
    memcpy(before_cache, emulator->sdm_read_cache, sizeof(before_cache));
    uint32_t before_counter = file->state.data.sdm_read_counter;

    aes_operation = 0;
    aes_cbc_operation = 0;
    fail_aes_operation = cmac_operation;
    fail_aes_cbc_operation = cbc_operation;
    fail_at = cmac_operation ? 1 : 0;
    munit_assert_false(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, before_counter);
    munit_assert_false(emulator->sdm_read_cache_valid);
    munit_assert_memory_equal(sizeof(before_cache), emulator->sdm_read_cache, before_cache);

    fail_at = 0;
    fail_aes_operation = 0;
    fail_aes_cbc_operation = 0;
    aes_operation = 0;
    aes_cbc_operation = 0;
    munit_assert_true(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, before_counter + 1);
    munit_assert_true(emulator->sdm_read_cache_valid);
    fault_link_close(&link);
}

static MunitResult
    test_sdm_crypto_failures_are_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    for(size_t operation = 1; operation <= 3; operation++)
        assert_sdm_fault_rolls_back_and_retries(operation, 0);
    for(size_t operation = 1; operation <= 3; operation++)
        assert_sdm_fault_rolls_back_and_retries(0, operation);
    return MUNIT_OK;
}

static MunitResult
    test_sdm_counter_and_chain_guards(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fail_at = 0;
    fail_cbc = false;
    fail_aes_operation = 0;
    fail_aes_cbc_operation = 0;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    DfcFile* file = configure_sdm_fault_file(&link);
    DfcEmulator* emulator = link.picc->emulator;

    file->state.data.sdm_read_counter = 0xFFFFFFu;
    munit_assert_false(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 0xFFFFFFu);

    file->state.data.sdm_read_counter = 41;
    emulator->command_chain_active = true;
    emulator->pending_chain_len = 7;
    emulator->pending_chain_offset = 0;
    memset(emulator->pending_chain, 0xA5, emulator->pending_chain_len);
    munit_assert_false(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, 41);
    for(size_t i = 0; i < emulator->pending_chain_len; i++)
        munit_assert_uint8(emulator->pending_chain[i], ==, 0xA5);

    fault_link_close(&link);
    return MUNIT_OK;
}

static MunitResult
    test_sdm_cache_hit_skips_rollback_scratch(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    DfcFile* file = configure_sdm_fault_file(&link);
    DfcEmulator* emulator = link.picc->emulator;
    uint8_t cache_before[DFC_SDM_READ_CACHE_SIZE];
    uint8_t scratch_before[DFC_SDM_READ_CACHE_SIZE];

    emulator->sdm_read_cache_valid = true;
    emulator->sdm_read_cache_file_number = file->number;
    emulator->sdm_read_cache_family = DfcSdmReadFamilyNative;
    emulator->sdm_read_cache_len = 73;
    memset(emulator->sdm_read_cache, 0x5A, sizeof(emulator->sdm_read_cache));
    memset(scratch_before, 0xC7, sizeof(scratch_before));
    memcpy(
        emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE, scratch_before, sizeof(scratch_before));
    memcpy(cache_before, emulator->sdm_read_cache, sizeof(cache_before));
    const uint32_t counter_before = file->state.data.sdm_read_counter;

    munit_assert_true(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before);
    munit_assert_true(emulator->sdm_read_cache_valid);
    munit_assert_uint8(emulator->sdm_read_cache_file_number, ==, file->number);
    munit_assert_size(emulator->sdm_read_cache_len, ==, 73);
    munit_assert_memory_equal(sizeof(cache_before), emulator->sdm_read_cache, cache_before);
    munit_assert_memory_equal(
        sizeof(scratch_before), emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE, scratch_before);

    /* A cached result must not bypass the in-flight command-chain guard. */
    emulator->command_chain_active = true;
    munit_assert_false(dfc_emulator_render_sdm_read(emulator, file));
    munit_assert_memory_equal(sizeof(cache_before), emulator->sdm_read_cache, cache_before);
    munit_assert_memory_equal(
        sizeof(scratch_before), emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE, scratch_before);

    fault_link_close(&link);
    return MUNIT_OK;
}

static void assert_sdm_random_failure_is_atomic(bool iso_read) {
    static FaultLink link;
    const uint8_t key[DFC_AES_KEY_LENGTH] = {0x11};
    fail_random_fill = false;
    fault_link_open(&link, DFC_CMD_AUTHENTICATE_AES, DFC_KEY_TYPE_AES, key, sizeof(key));
    DfcFile* file = configure_sdm_fault_file(&link);
    DfcEmulator* emulator = link.picc->emulator;
    link.credential.card.generation = DfcGenerationEv3;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    if(iso_read) dfc_emulator_retire_authentication(emulator);

    emulator->sdm_read_cache_valid = false;
    emulator->sdm_read_cache_file_number = 0xA5;
    emulator->sdm_read_cache_family = 0x5A;
    emulator->sdm_read_cache_len = 17;
    memset(emulator->sdm_read_cache, 0x5A, sizeof(emulator->sdm_read_cache));
    const uint32_t counter_before = file->state.data.sdm_read_counter;
    const uint8_t cache_file_before = emulator->sdm_read_cache_file_number;
    const uint8_t cache_family_before = emulator->sdm_read_cache_family;
    const size_t cache_len_before = emulator->sdm_read_cache_len;
    uint8_t cache_before[DFC_SDM_READ_CACHE_SIZE];
    memcpy(cache_before, emulator->sdm_read_cache, sizeof(cache_before));
    const DfcEmulatorSelectedApplication selection_before = emulator->selected_application;
    const size_t app_index_before = emulator->selected_app_index;
    const uint8_t auth_cipher_before = emulator->auth_cipher;
    const uint8_t auth_key_before = emulator->auth_key_no;
    DfcSecureMessaging secure_messaging_before = *emulator->secure_messaging;

    const uint8_t native_read[] = {
        DFC_ISO7816_CLA_WRAPPER, DFC_CMD_READ_DATA, 0, 0, 7, 1, 0, 0, 0, 3, 0, 0, 0};
    const uint8_t iso_read_binary[] = {0, DFC_ISO7816_INS_READ_BINARY, 0, 0, 3};
    const uint8_t* command = iso_read ? iso_read_binary : native_read;
    const size_t command_len = iso_read ? sizeof(iso_read_binary) : sizeof(native_read);
    if(iso_read) {
        link.picc->iso_file_selected = true;
        link.picc->iso_file_index = 0;
    }
    const bool iso_file_selected_before = link.picc->iso_file_selected;
    const size_t iso_file_index_before = link.picc->iso_file_index;
    uint8_t response[16];
    size_t response_len = 0;

    random_fill_calls = 0;
    fail_random_fill = true;
    DfcVirtualPiccStatus random_status = dfc_virtual_picc_iso_dep_exchange(
        link.picc, command, command_len, response, sizeof(response), &response_len);
    munit_assert_int(random_status, ==, DfcVirtualPiccStatusProtocolError);
    fail_random_fill = false;
    munit_assert_size(random_fill_calls, >, 0);
    munit_assert_size(response_len, ==, 0);
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before);
    munit_assert_false(emulator->sdm_read_cache_valid);
    munit_assert_uint8(emulator->sdm_read_cache_file_number, ==, cache_file_before);
    munit_assert_uint8(emulator->sdm_read_cache_family, ==, cache_family_before);
    munit_assert_size(emulator->sdm_read_cache_len, ==, cache_len_before);
    munit_assert_memory_equal(sizeof(cache_before), emulator->sdm_read_cache, cache_before);
    munit_assert_int(emulator->selected_application, ==, selection_before);
    munit_assert_size(emulator->selected_app_index, ==, app_index_before);
    munit_assert_uint8(emulator->auth_cipher, ==, auth_cipher_before);
    munit_assert_uint8(emulator->auth_key_no, ==, auth_key_before);
    munit_assert_memory_equal(
        sizeof(secure_messaging_before), emulator->secure_messaging, &secure_messaging_before);
    munit_assert_int(link.picc->iso_file_selected, ==, iso_file_selected_before);
    munit_assert_size(link.picc->iso_file_index, ==, iso_file_index_before);

    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    size_t expected_response_len = iso_read ? 5 : 13;
    munit_assert_size(response_len, ==, expected_response_len);
    munit_assert_memory_equal(
        2,
        response + response_len - 2,
        iso_read ? ((uint8_t[]){0x90, 0x00}) : ((uint8_t[]){0x91, DFC_STATUS_OK}));
    munit_assert_uint32(file->state.data.sdm_read_counter, ==, counter_before + 1);
    munit_assert_true(emulator->sdm_read_cache_valid);
    munit_assert_uint8(emulator->sdm_read_cache_file_number, ==, file->number);
    munit_assert_uint8(
        emulator->sdm_read_cache_family,
        ==,
        iso_read ? DfcSdmReadFamilyIso7816 : DfcSdmReadFamilyNative);
    fault_link_close(&link);
}

static MunitResult
    test_sdm_random_padding_failure_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    assert_sdm_random_failure_is_atomic(false);
    assert_sdm_random_failure_is_atomic(true);
    return MUNIT_OK;
}
#endif

#if DFC_ENABLE_DELEGATED_APPLICATIONS && DFC_ENABLE_EV2_SECURE_MESSAGING
static const uint8_t dam_auth_key[DFC_AES_KEY_LENGTH] =
    {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40};
static const uint8_t dam_mac_key[DFC_AES_KEY_LENGTH] =
    {0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x50};
static const uint8_t dam_encryption_key[DFC_AES_KEY_LENGTH] =
    {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x60};

static void fault_link_open_ev2_dam(FaultLink* link) {
    memset(link, 0, sizeof(*link));
    const uint8_t uid[DFC_DESFIRE_UID_LEN] = {0x04, 1, 2, 3, 4, 5, 6};
    memcpy(link->credential.uid, uid, sizeof(uid));
    link->credential.uid_len = sizeof(uid);
    link->credential.card.generation = DfcGenerationEv2;
    link->credential.picc_key_settings_1 = DFC_KS1_FREE_CREATE_DELETE;
    link->credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    link->credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    link->credential.picc_has_auth_commands = true;
    link->credential.picc_auth_commands = DFC_AUTH_COMMAND_AES | DFC_AUTH_COMMAND_EV2_FIRST;
    munit_assert_true(dfc_credential_keys_resize(&link->credential, NULL, 1, DFC_AES_KEY_LENGTH));
    link->credential.picc_has_dam_keys = true;
    memcpy(link->credential.picc_dam_auth_key, dam_auth_key, sizeof(dam_auth_key));
    memcpy(link->credential.picc_dam_mac_key, dam_mac_key, sizeof(dam_mac_key));
    memcpy(
        link->credential.picc_dam_encryption_key, dam_encryption_key, sizeof(dam_encryption_key));
    link->picc = dfc_virtual_picc_session_alloc(&link->credential);
    munit_assert_not_null(link->picc);
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(link->picc, &activation), ==, DfcVirtualPiccStatusOk);
    dfc_reader_session_init(&link->reader);

    DfcCommand select;
    const uint8_t picc_aid[3] = {0};
    munit_assert_int(dfc_command_select_application(&select, picc_aid, NULL), ==, DfcCommandOk);
    send_plain(link, &select);
}

static void fault_link_authenticate_ev2_dam(FaultLink* link) {
    uint8_t random_a[DFC_EV2_RANDOM_LENGTH];
    uint8_t capabilities[DFC_EV2_CAPABILITY_LENGTH] = {0};
    for(size_t i = 0; i < sizeof(random_a); i++)
        random_a[i] = (uint8_t)(0x30 + i);
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_reader_authenticate_ev2_begin(
            &exchange,
            &link->reader,
            DfcReaderFramingIso7816,
            true,
            DFC_DAM_AUTH_KEY_NUMBER,
            dam_auth_key,
            random_a,
            capabilities,
            sizeof(capabilities)),
        ==,
        DfcReaderOk);
    munit_assert_int(run_exchange(link, &exchange), ==, DfcReaderOk);
}

static void begin_delegated_creation(DfcReaderExchange* exchange, FaultLink* link) {
    const DfcCommandCreateDelegatedApplication app = {
        {0x0A, 0x0B, 0x0C}, 0x0001, 0x00, 0x0040, 0x0F, DFC_KEY_TYPE_AES | 1};
    const uint8_t prefix[DFC_DELEGATED_RANDOM_PREFIX_LENGTH] = {1, 2, 3, 4, 5, 6, 7};
    const uint8_t initial[DFC_AES_KEY_LENGTH] = {
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xAB,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD,
        0xCD};
    munit_assert_int(
        dfc_reader_create_delegated_application_begin(
            exchange,
            &link->reader,
            DfcReaderFramingIso7816,
            &app,
            dam_encryption_key,
            dam_mac_key,
            prefix,
            initial,
            sizeof(initial),
            0x03),
        ==,
        DfcReaderOk);
}

static MunitResult test_delegated_begin_crypto_failures_are_terminal(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    const DfcCommandCreateDelegatedApplication app = {
        {0x0A, 0x0B, 0x0C}, 0x0001, 0x00, 0x0040, 0x0F, DFC_KEY_TYPE_AES | 1};
    const uint8_t prefix[DFC_DELEGATED_RANDOM_PREFIX_LENGTH] = {1, 2, 3, 4, 5, 6, 7};
    const uint8_t initial[DFC_AES_KEY_LENGTH] = {0xAB};
    DfcReaderSession session = {0};
    session.auth_mode = DFC_READER_AUTH_EV2;
    memset(session.ev2_mac_key, 0x39, sizeof(session.ev2_mac_key));
    DfcReaderSession session_before = session;

    for(size_t failure = 0; failure < 3; failure++) {
        DfcReaderExchange exchange;
        memset(&exchange, 0xA5, sizeof(exchange));
        fail_cbc = failure == 0;
        aes_operation = 0;
        fail_at = failure == 0 ? 0 : 1;
        fail_aes_operation = failure == 0 ? 0 : failure;
        munit_assert_int(
            dfc_reader_create_delegated_application_begin(
                &exchange,
                &session,
                DfcReaderFramingIso7816,
                &app,
                dam_encryption_key,
                dam_mac_key,
                prefix,
                initial,
                sizeof(initial),
                0x03),
            ==,
            DfcReaderIntegrityError);
        for(size_t i = 0; i < sizeof(exchange); i++)
            munit_assert_uint8(((const uint8_t*)&exchange)[i], ==, 0);
        munit_assert_memory_equal(sizeof(session_before), &session, &session_before);
    }
    fail_cbc = false;
    fail_at = 0;
    fail_aes_operation = 0;
    return MUNIT_OK;
}

static MunitResult
    test_delegated_response_mac_failure_rolls_back(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static FaultLink link;
    static uint8_t key_pool_before[DFC_KEY_POOL_SIZE];
    fail_at = 0;
    fail_aes_operation = 0;
    fail_aes_cbc_operation = 0;
    fail_cbc = false;
    fail_random_fill = false;
    fault_link_open_ev2_dam(&link);
    fault_link_authenticate_ev2_dam(&link);

    size_t app_count_before = link.credential.num_apps;
    size_t key_pool_used_before = link.credential.key_pool_used;
    bool dirty_before = link.credential.dirty;
    memcpy(key_pool_before, link.credential.key_pool, sizeof(key_pool_before));
    uint16_t counter_before = link.picc->emulator->ev2_command_counter;

    DfcReaderExchange exchange;
    begin_delegated_creation(&exchange, &link);
    uint8_t command[DFC_COMMAND_MAX_APDU];
    size_t command_len = 0;
    uint8_t response[DFC_READER_MAX_RESPONSE + 16];
    size_t response_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, command, sizeof(command), &command_len),
        ==,
        DfcReaderPending);
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(&exchange, response, response_len, command, sizeof(command), &command_len),
        ==,
        DfcReaderPending);
    munit_assert_true(link.picc->emulator->ev2_session_active);
    munit_assert_uint8(link.picc->emulator->ev2_authenticated_key_no, ==, DFC_DAM_AUTH_KEY_NUMBER);
    munit_assert_true(link.credential.picc_has_dam_keys);

    aes_operation = 0;
    fail_aes_operation = 3;
    fail_at = 1;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, command, command_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_int(
        dfc_reader_step(&exchange, response, response_len, command, sizeof(command), &command_len),
        ==,
        DfcReaderCardError);
    munit_assert_size(link.credential.num_apps, ==, app_count_before);
    munit_assert_size(link.credential.key_pool_used, ==, key_pool_used_before);
    munit_assert_memory_equal(sizeof(key_pool_before), link.credential.key_pool, key_pool_before);
    munit_assert_int(link.credential.dirty, ==, dirty_before);
    munit_assert_uint16(link.picc->emulator->ev2_command_counter, ==, counter_before);
    munit_assert_false(link.picc->emulator->ev2_session_active);
    assert_zeroed(
        link.picc->emulator->ev2_session_encryption_key,
        sizeof(link.picc->emulator->ev2_session_encryption_key));
    assert_zeroed(
        link.picc->emulator->ev2_session_mac_key,
        sizeof(link.picc->emulator->ev2_session_mac_key));

    fail_at = 0;
    fail_aes_operation = 0;
    dfc_reader_session_clear(&link.reader);
    fault_link_authenticate_ev2_dam(&link);
    begin_delegated_creation(&exchange, &link);
    munit_assert_int(run_exchange(&link, &exchange), ==, DfcReaderOk);
    const uint8_t aid[3] = {0x0A, 0x0B, 0x0C};
    munit_assert_not_null(dfc_credential_find_application_desfire_order(&link.credential, aid));
    munit_assert_size(link.credential.num_apps, ==, app_count_before + 1);
    fault_link_close(&link);
    return MUNIT_OK;
}
#endif

static MunitResult
    test_change_key_cryptogram_cleanup_exits(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t new_key[DFC_AES_KEY_LENGTH] = {0x11};
    uint8_t output[64];
    size_t output_len = 0;
    DfcReaderSession session;

    memset(&session, 0, sizeof(session));
    memset(output, 0xA5, sizeof(output));
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session,
            0,
            new_key,
            sizeof(new_key),
            NULL,
            false,
            0,
            output,
            sizeof(output),
            &output_len),
        ==,
        DfcReaderInvalid);

    session.auth_mode = DFC_CMD_AUTHENTICATE_LEGACY;
    session.key_no = 0;
    session.sm.cipher = DFC_CMD_AUTHENTICATE_LEGACY;
    session.sm.session_key_len = sizeof(new_key);
    memset(session.sm.session_key, 0x22, session.sm.session_key_len);
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session, 0, new_key, sizeof(new_key), NULL, false, 0, output, 0, &output_len),
        ==,
        DfcReaderBufferTooSmall);

    memset(output, 0xA5, sizeof(output));
    fail_at = 1;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session,
            0,
            new_key,
            sizeof(new_key),
            NULL,
            false,
            0,
            output,
            sizeof(output),
            &output_len),
        ==,
        DfcReaderInvalid);
    munit_assert_memory_equal(24, output, ((uint8_t[24]){0}));
    fail_at = 0;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session,
            0,
            new_key,
            sizeof(new_key),
            NULL,
            false,
            0,
            output,
            sizeof(output),
            &output_len),
        ==,
        DfcReaderOk);
    munit_assert_size(output_len, ==, 24);

    memset(&session, 0, sizeof(session));
    session.auth_mode = DFC_CMD_AUTHENTICATE_AES;
    session.key_no = 0;
    session.sm.cipher = DFC_CMD_AUTHENTICATE_AES;
    session.sm.session_key_len = DFC_AES_KEY_LENGTH;
    memset(session.sm.session_key, 0x33, session.sm.session_key_len);
    memset(session.sm.iv, 0x44, sizeof(session.sm.iv));
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session, 0, new_key, sizeof(new_key), NULL, true, 7, output, 0, &output_len),
        ==,
        DfcReaderBufferTooSmall);

    memset(output, 0xA5, sizeof(output));
    fail_cbc = true;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session,
            0,
            new_key,
            sizeof(new_key),
            NULL,
            true,
            7,
            output,
            sizeof(output),
            &output_len),
        ==,
        DfcReaderInvalid);
    munit_assert_memory_equal(32, output, ((uint8_t[32]){0}));
    fail_cbc = false;
    munit_assert_int(
        dfc_reader_change_key_cryptogram(
            &session,
            0,
            new_key,
            sizeof(new_key),
            NULL,
            true,
            7,
            output,
            sizeof(output),
            &output_len),
        ==,
        DfcReaderOk);
    munit_assert_size(output_len, ==, 32);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/authentication/native-allocation",
     test_native_reauthentication_reuses_retired_session_allocation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authentication/native-initial-allocation-failure",
     test_native_initial_authentication_allocation_failure,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authentication/iso7816-allocation",
     test_iso7816_reauthentication_reuses_retired_session_allocation,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/authentication/iso7816-initial-allocation-failure",
     test_iso7816_initial_authentication_allocation_failure,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/authentication/ev2-capability-failures",
     test_ev2_crypto_failures_clear_accepted_session,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if DFC_ENABLE_TRANSACTION_MAC && DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/transaction-mac/failure-aborts",
     test_transaction_mac_failures_abort,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac/transcript-bounds",
     test_transaction_transcript_bounds,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac/streaming-atomic",
     test_transaction_streaming_failures_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac/counter-boundary",
     test_transaction_counter_does_not_wrap,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac/reader-id-transaction",
     test_commit_reader_id_is_transactional,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/transaction-mac/create-rollback",
     test_transaction_file_creation_rolls_back,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#if DFC_ENABLE_PROXIMITY_CHECK
    {"/proximity/terminal-wipe",
     test_proximity_terminal_paths_wipe_state,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#endif
    {"/cmac/positions",
     test_cmac_failure_positions_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/ev2-session-keys",
     test_ev2_session_key_derivation_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/wrap", test_mac_wrap_propagates_every_failure, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/cmac/reject-zero-tag",
     test_failed_cmac_cannot_authenticate_zero_tag,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/update",
     test_ev1_update_propagates_every_failure,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/invalid-key-widths",
     test_invalid_key_widths_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cmac/in-place-output",
     test_in_place_failure_restores_spare_byte,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cbc/atomic", test_cbc_failures_are_atomic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/cbc/change-key-cleanup",
     test_change_key_cryptogram_cleanup_exits,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/reader/prepare-crypto-terminal",
     test_reader_prepare_crypto_failures_are_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/get-value/protection-failures",
     test_get_value_protection_failures_fail_closed,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/response-mac/retry",
     test_response_mac_failures_allow_retry,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/response-mac/call-chain",
     test_response_mac_call_chains_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/command-mac/retry",
     test_command_mac_failures_allow_retry,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/cbc/crc-retry", test_crc_failures_allow_retry, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if DFC_ENABLE_SDM
    {"/sdm/crypto-atomicity",
     test_sdm_crypto_failures_are_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/sdm/counter-chain-guards",
     test_sdm_counter_and_chain_guards,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/sdm/cache-hit-skips-rollback-scratch",
     test_sdm_cache_hit_skips_rollback_scratch,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/sdm/random-padding-atomicity",
     test_sdm_random_padding_failure_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS && DFC_ENABLE_EV2_SECURE_MESSAGING
    {"/delegated/begin-crypto-terminal",
     test_delegated_begin_crypto_failures_are_terminal,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/delegated/response-mac-rollback",
     test_delegated_response_mac_failure_rolls_back,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/secure-messaging-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
