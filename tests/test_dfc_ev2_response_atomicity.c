#include "munit/munit.h"

#include "dfc_ev2.h"
#include "dfc_ev2_crypto.h"

#include <string.h>

#if DFC_ENABLE_EMULATOR && DFC_ENABLE_EV2_SECURE_MESSAGING

static bool fail_encrypt;
static bool fail_mac;
static bool unexpected_encrypt_len;
static DfcFile encrypted_file;
static uint16_t observed_encrypt_counter;
static uint16_t observed_mac_counter;

DfcFile* dfc_credential_find_file_in_app(
    DfcCredential* credential,
    size_t application_index,
    uint8_t file_number) {
    (void)credential;
    (void)application_index;
    return file_number == encrypted_file.number ? &encrypted_file : NULL;
}

bool dfc_ev2_encrypt_data(
    const uint8_t encryption_key[DFC_AES_KEY_LENGTH],
    DfcEv2Direction direction,
    uint16_t counter,
    const uint8_t transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH],
    const uint8_t* clear,
    size_t clear_len,
    uint8_t* encrypted,
    size_t encrypted_capacity,
    size_t* encrypted_len) {
    (void)encryption_key;
    (void)direction;
    (void)counter;
    (void)transaction_identifier;
    observed_encrypt_counter = counter;
    if(fail_encrypt) return false;
    size_t padded_len = (clear_len / DFC_AES_KEY_LENGTH + 1) * DFC_AES_KEY_LENGTH;
    if(padded_len > encrypted_capacity) return false;
    memset(encrypted, 0, padded_len);
    memcpy(encrypted, clear, clear_len);
    encrypted[clear_len] = DFC_EV2_PADDING_MARKER;
    *encrypted_len = unexpected_encrypt_len ? padded_len - 1 : padded_len;
    return true;
}

bool dfc_ev2_decrypt_data(
    const uint8_t encryption_key[DFC_AES_KEY_LENGTH],
    DfcEv2Direction direction,
    uint16_t counter,
    const uint8_t transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH],
    const uint8_t* encrypted,
    size_t encrypted_len,
    uint8_t* clear,
    size_t* clear_len,
    bool allow_unpadded) {
    (void)encryption_key;
    (void)direction;
    (void)counter;
    (void)transaction_identifier;
    (void)encrypted;
    (void)encrypted_len;
    (void)clear;
    (void)clear_len;
    (void)allow_unpadded;
    return false;
}

bool dfc_ev2_mac(
    const uint8_t mac_key[DFC_AES_KEY_LENGTH],
    uint8_t lead,
    uint16_t counter,
    const uint8_t transaction_identifier[DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH],
    const uint8_t* first,
    size_t first_len,
    const uint8_t* second,
    size_t second_len,
    uint8_t output[DFC_WIRE_MAC_LENGTH]) {
    (void)mac_key;
    (void)lead;
    (void)counter;
    (void)transaction_identifier;
    (void)first;
    (void)first_len;
    (void)second;
    (void)second_len;
    observed_mac_counter = counter;
    if(fail_mac) return false;
    memset(output, 0x5A, DFC_WIRE_MAC_LENGTH);
    return true;
}

bool dfc_ev2_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

static void assert_failure_is_atomic(
    DfcEmulator* emulator,
    const uint8_t* command,
    size_t command_len,
    const uint8_t* clear_response,
    size_t clear_response_len,
    size_t secured_capacity) {
    uint8_t secured[DFC_WORKER_MAX_BUFFER_SIZE + DFC_WIRE_MAC_LENGTH + 1];
    memset(secured, 0xA5, sizeof(secured));
    uint8_t before[sizeof(secured)];
    memcpy(before, secured, sizeof(before));
    size_t secured_len = 0xCAFE;
    uint16_t counter = emulator->ev2_command_counter;

    munit_assert_false(dfc_ev2_protect_response(
        emulator,
        command,
        command_len,
        clear_response,
        clear_response_len,
        secured,
        secured_capacity,
        &secured_len));
    munit_assert_uint16(emulator->ev2_command_counter, ==, counter);
    munit_assert_size(secured_len, ==, 0xCAFE);
    munit_assert_memory_equal(sizeof(secured), secured, before);
}

static void init_emulator(DfcEmulator* emulator, DfcCredential* credential) {
    memset(emulator, 0, sizeof(*emulator));
    memset(credential, 0, sizeof(*credential));
    emulator->credential = credential;
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
    emulator->ev2_command_counter = 7;
    fail_encrypt = false;
    fail_mac = false;
    unexpected_encrypt_len = false;
    observed_encrypt_counter = 0;
    observed_mac_counter = 0;
}

static MunitResult test_capacity_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    const uint8_t response[] = {DFC_STATUS_OK, 0x11, 0x22};
    assert_failure_is_atomic(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        sizeof(response) + DFC_WIRE_MAC_LENGTH - 1);
    return MUNIT_OK;
}

static MunitResult
    test_counter_limit_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.ev2_command_counter = UINT16_MAX;
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    const uint8_t response[] = {DFC_STATUS_OK};
    assert_failure_is_atomic(
        &emulator, command, sizeof(command), response, sizeof(response), DFC_WIRE_MAC_LENGTH + 1);
    return MUNIT_OK;
}

static MunitResult test_mac_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    fail_mac = true;
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    const uint8_t response[] = {DFC_STATUS_OK, 0x11};
    assert_failure_is_atomic(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        sizeof(response) + DFC_WIRE_MAC_LENGTH);
    return MUNIT_OK;
}

static MunitResult test_encryption_failure_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.selected_application = DfcEmulatorSelectedApplicationApp;
    encrypted_file.number = 1;
    encrypted_file.comm_settings = DFC_COMM_ENCIPHERED;
    fail_encrypt = true;
    const uint8_t command[] = {DFC_CMD_READ_DATA, 1};
    const uint8_t response[] = {DFC_STATUS_OK, 0x11};
    assert_failure_is_atomic(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        sizeof(response) + DFC_WIRE_MAC_LENGTH);
    return MUNIT_OK;
}

static MunitResult
    test_unexpected_encrypted_length_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.selected_application = DfcEmulatorSelectedApplicationApp;
    encrypted_file.number = 1;
    encrypted_file.comm_settings = DFC_COMM_ENCIPHERED;
    unexpected_encrypt_len = true;
    const uint8_t command[] = {DFC_CMD_READ_DATA, 1};
    const uint8_t response[] = {DFC_STATUS_OK, 0x11};
    assert_failure_is_atomic(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        DFC_AES_KEY_LENGTH + DFC_WIRE_MAC_LENGTH + 1);
    return MUNIT_OK;
}

static MunitResult
    test_oversize_plain_response_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    uint8_t response[DFC_WORKER_MAX_BUFFER_SIZE + 2] = {DFC_STATUS_OK};
    assert_failure_is_atomic(
        &emulator, command, sizeof(command), response, sizeof(response), SIZE_MAX);
    return MUNIT_OK;
}

static MunitResult
    test_oversize_encrypted_response_is_atomic(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.selected_application = DfcEmulatorSelectedApplicationApp;
    encrypted_file.number = 1;
    encrypted_file.comm_settings = DFC_COMM_ENCIPHERED;
    const uint8_t command[] = {DFC_CMD_READ_DATA, 1};
    uint8_t response[DFC_WORKER_MAX_BUFFER_SIZE + 1] = {DFC_STATUS_OK};
    assert_failure_is_atomic(
        &emulator, command, sizeof(command), response, sizeof(response), SIZE_MAX);
    return MUNIT_OK;
}

static MunitResult test_encrypted_boundary_succeeds(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.selected_application = DfcEmulatorSelectedApplicationApp;
    encrypted_file.number = 1;
    encrypted_file.comm_settings = DFC_COMM_ENCIPHERED;
    const uint8_t command[] = {DFC_CMD_READ_DATA, 1};
    uint8_t response[DFC_WORKER_MAX_BUFFER_SIZE] = {DFC_STATUS_OK};
    uint8_t secured[DFC_WORKER_MAX_BUFFER_SIZE + DFC_WIRE_MAC_LENGTH + 1];
    size_t secured_len = 0;

    munit_assert_true(dfc_ev2_protect_response(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        secured,
        sizeof(secured),
        &secured_len));
    munit_assert_uint16(emulator.ev2_command_counter, ==, 8);
    munit_assert_uint16(observed_encrypt_counter, ==, 8);
    munit_assert_uint16(observed_mac_counter, ==, 8);
    munit_assert_size(secured_len, ==, sizeof(secured));
    return MUNIT_OK;
}

static MunitResult
    test_success_commits_counter_and_output(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    const uint8_t response[] = {DFC_STATUS_OK, 0x11, 0x22};
    uint8_t secured[sizeof(response) + DFC_WIRE_MAC_LENGTH];
    size_t secured_len = 0;

    munit_assert_true(dfc_ev2_protect_response(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        secured,
        sizeof(secured),
        &secured_len));
    munit_assert_uint16(emulator.ev2_command_counter, ==, 8);
    munit_assert_uint16(observed_mac_counter, ==, 8);
    munit_assert_size(secured_len, ==, sizeof(secured));
    munit_assert_memory_equal(sizeof(response), secured, response);
    for(size_t i = sizeof(response); i < sizeof(secured); i++)
        munit_assert_uint8(secured[i], ==, 0x5A);
    return MUNIT_OK;
}

static MunitResult test_last_counter_value_succeeds(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcEmulator emulator;
    DfcCredential credential;
    init_emulator(&emulator, &credential);
    emulator.ev2_command_counter = UINT16_MAX - 1;
    const uint8_t command[] = {DFC_CMD_GET_VERSION};
    const uint8_t response[] = {DFC_STATUS_OK};
    uint8_t secured[sizeof(response) + DFC_WIRE_MAC_LENGTH];
    size_t secured_len = 0;

    munit_assert_true(dfc_ev2_protect_response(
        &emulator,
        command,
        sizeof(command),
        response,
        sizeof(response),
        secured,
        sizeof(secured),
        &secured_len));
    munit_assert_uint16(emulator.ev2_command_counter, ==, UINT16_MAX);
    munit_assert_uint16(observed_mac_counter, ==, UINT16_MAX);
    munit_assert_size(secured_len, ==, sizeof(secured));
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/capacity", test_capacity_failure_is_atomic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/counter-limit",
     test_counter_limit_failure_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/mac-failure", test_mac_failure_is_atomic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/encryption-failure",
     test_encryption_failure_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/unexpected-encrypted-length",
     test_unexpected_encrypted_length_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/oversize-plain",
     test_oversize_plain_response_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/oversize-encrypted",
     test_oversize_encrypted_response_is_atomic,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/encrypted-boundary",
     test_encrypted_boundary_succeeds,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/success", test_success_commits_counter_and_output, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/last-counter-value",
     test_last_counter_value_succeeds,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

#else
static MunitTest tests[] = {{NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
#endif

static const MunitSuite suite =
    {"/dfc_ev2_response_atomicity", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
