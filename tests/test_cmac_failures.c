#include "munit.h"

#include "aes_cmac.h"
#include "des_cmac.h"
#include "dfc_an10922.h"
#include "dfc_crypto_internal.h"

#include <string.h>

static size_t aes_call;
static size_t des_call;
static size_t aes_init;
static size_t des_init;
static size_t fail_at;

bool dfc_crypto_aes_block_init(DfcCryptoAesBlock* block, const uint8_t* key, size_t key_len) {
    (void)key;
    memset(block, 0, sizeof(*block));
    block->initialized = key_len == 16;
    aes_init++;
    aes_call = 0;
    return block->initialized;
}

bool dfc_crypto_aes_block_encrypt(
    DfcCryptoAesBlock* block,
    const uint8_t input[16],
    uint8_t output[16]) {
    (void)block;
    aes_call++;
    if(aes_call == fail_at) return false;
    for(size_t i = 0; i < 16; i++)
        output[i] = input[i] ^ (uint8_t)(0x31 + aes_call);
    return true;
}

void dfc_crypto_aes_block_clear(DfcCryptoAesBlock* block) {
    memset(block, 0, sizeof(*block));
}

bool dfc_crypto_des_block_init(
    DfcCryptoDesBlock* block,
    bool encrypt,
    const uint8_t* key,
    size_t key_len) {
    (void)key;
    memset(block, 0, sizeof(*block));
    block->key_len = key_len;
    block->encrypt = encrypt;
    block->initialized = key_len == 8 || key_len == 16 || key_len == 24;
    des_init++;
    des_call = 0;
    return block->initialized;
}

bool dfc_crypto_des_block_crypt(
    DfcCryptoDesBlock* block,
    const uint8_t input[8],
    uint8_t output[8]) {
    (void)block;
    des_call++;
    if(des_call == fail_at) return false;
    for(size_t i = 0; i < 8; i++)
        output[i] = input[i] ^ (uint8_t)(0x51 + des_call);
    return true;
}

void dfc_crypto_des_block_clear(DfcCryptoDesBlock* block) {
    memset(block, 0, sizeof(*block));
}

static MunitResult test_aes_failure_positions(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t key[16] = {0};
    uint8_t message[32] = {0};
    uint8_t output[16];
    for(fail_at = 1; fail_at <= 3; fail_at++) {
        aes_init = 0;
        memset(output, 0xA5, sizeof(output));
        munit_assert_false(aes_cmac(key, sizeof(key), message, sizeof(message), output));
        munit_assert_size(aes_init, ==, 1);
        uint8_t zero[16] = {0};
        munit_assert_memory_equal(sizeof(output), output, zero);
    }
    return MUNIT_OK;
}

static MunitResult test_des_failure_positions(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t key[24] = {0};
    uint8_t message[16] = {0};
    uint8_t output[8];
    for(size_t key_len = 8; key_len <= 24; key_len += 8) {
        for(fail_at = 1; fail_at <= 3; fail_at++) {
            des_init = 0;
            memset(output, 0xA5, sizeof(output));
            munit_assert_false(des_cmac(key, key_len, message, sizeof(message), output));
            munit_assert_size(des_init, ==, 1);
            uint8_t zero[8] = {0};
            munit_assert_memory_equal(sizeof(output), output, zero);
        }
    }
    return MUNIT_OK;
}

static MunitResult test_an10922_failure_positions(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    uint8_t key[24] = {0};
    uint8_t input[15] = {0};
    uint8_t output[24];
    uint8_t zero[24] = {0};

    for(fail_at = 1; fail_at <= 3; fail_at++) {
        aes_init = 0;
        memset(output, 0xa5, sizeof(output));
        munit_assert_false(
            dfc_an10922_diversify(DfcAn10922Aes128, key, 16, input, sizeof(input), output, 16));
        munit_assert_size(aes_init, ==, 1);
        munit_assert_memory_equal(16, output, zero);
    }
    for(size_t key_len = 16; key_len <= 24; key_len += 8) {
        size_t operation_count = key_len == 16 ? 5 : 7;
        DfcAn10922Algorithm algorithm = key_len == 16 ? DfcAn10922Tdea2 : DfcAn10922Tdea3;
        for(fail_at = 1; fail_at <= operation_count; fail_at++) {
            des_init = 0;
            memset(output, 0xa5, sizeof(output));
            munit_assert_false(dfc_an10922_diversify(
                algorithm, key, key_len, input, sizeof(input), output, key_len));
            munit_assert_size(des_init, ==, 1);
            munit_assert_memory_equal(key_len, output, zero);
        }
    }
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/aes/all-blocks", test_aes_failure_positions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des/all-blocks", test_des_failure_positions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/an10922/all-blocks",
     test_an10922_failure_positions,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {"/cmac-failure", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
