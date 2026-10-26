#include <stdint.h>
#include <string.h>

#include "dfc_an10922.h"
#include "dfc_build_config.h"

static int check_algorithm(
    DfcAn10922Algorithm algorithm,
    const uint8_t* key,
    size_t key_length,
    const uint8_t* input,
    size_t input_length,
    const uint8_t* expected,
    size_t output_length,
    bool enabled) {
    uint8_t output[24] = {0};
    bool success = dfc_an10922_diversify(
        algorithm, key, key_length, input, input_length, output, output_length);
    return success == enabled && (!enabled || memcmp(output, expected, output_length) == 0) ? 0 :
                                                                                              1;
}

int main(void) {
    static const uint8_t aes_key[16] = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff};
    static const uint8_t aes_input[17] = {
        0x04,
        0x78,
        0x2e,
        0x21,
        0x80,
        0x1d,
        0x80,
        0x30,
        0x42,
        0xf5,
        0x4e,
        0x58,
        0x50,
        0x20,
        0x41,
        0x62,
        0x75};
    static const uint8_t aes_expected[16] = {
        0xa8,
        0xdd,
        0x63,
        0xa3,
        0xb8,
        0x9d,
        0x54,
        0xb3,
        0x7c,
        0xa8,
        0x02,
        0x47,
        0x3f,
        0xda,
        0x91,
        0x75};
    static const uint8_t des_input[15] = {
        0x04, 0x78, 0x2e, 0x21, 0x80, 0x1d, 0x80, 0x30, 0x42, 0xf5, 0x4e, 0x58, 0x50, 0x20, 0x41};
    static const uint8_t des_expected[16] = {
        0x16,
        0xf9,
        0x58,
        0x7d,
        0x9e,
        0x89,
        0x10,
        0xc9,
        0x6b,
        0x96,
        0x48,
        0xd0,
        0x06,
        0x10,
        0x7d,
        0xd7};

    return check_algorithm(
               DfcAn10922Aes128,
               aes_key,
               sizeof(aes_key),
               aes_input,
               sizeof(aes_input),
               aes_expected,
               sizeof(aes_expected),
               DFC_ENABLE_AES_CRYPTO) ||
           check_algorithm(
               DfcAn10922Tdea2,
               aes_key,
               sizeof(aes_key),
               des_input,
               sizeof(des_input),
               des_expected,
               sizeof(des_expected),
               DFC_ENABLE_DES_CRYPTO);
}
