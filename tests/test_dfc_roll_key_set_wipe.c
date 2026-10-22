#include "munit/munit.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define dfc_secure_wipe dfc_test_observed_secure_wipe
#include "../src/dfc_credential.c"
#undef dfc_secure_wipe

static size_t observed_wipe_count;
static size_t observed_wipe_length;
static size_t expected_secret_length;
static uint8_t expected_secret_byte;
static bool observed_secret;
static bool observed_zeroed_buffer;

void dfc_test_observed_secure_wipe(void* buffer, size_t length) {
    uint8_t* bytes = buffer;
    bool secret_matches = length >= expected_secret_length;
    for(size_t i = 0; i < expected_secret_length && secret_matches; i++) {
        secret_matches = bytes[i] == expected_secret_byte;
    }

    volatile uint8_t* wipe = buffer;
    for(size_t i = 0; i < length; i++) {
        wipe[i] = 0;
    }

    bool all_zero = true;
    for(size_t i = 0; i < length; i++) {
        all_zero = all_zero && bytes[i] == 0;
    }

    observed_wipe_count++;
    observed_wipe_length = length;
    observed_secret = secret_matches;
    observed_zeroed_buffer = all_zero;
}

static MunitResult test_roll_wipes_complete_scratch(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    const size_t storage_widths[] = {DFC_AES_KEY_LENGTH, DFC_KEY_SET_MAXIMUM_24_BYTE};
    for(size_t width_index = 0; width_index < sizeof(storage_widths) / sizeof(storage_widths[0]);
        width_index++) {
        for(size_t rotations = 1; rotations <= 2; rotations++) {
            DfcCredential credential;
            memset(&credential, 0, sizeof(credential));
            dfc_credential_clear(&credential);

            const uint8_t aid[] = {0x01, 0x02, 0x03};
            DfcApplication* app = dfc_credential_create_application_desfire_order(
                &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 2);
            munit_assert_not_null(app);
            munit_assert_true(dfc_credential_key_sets_resize(
                &credential, app, 3, 2, DFC_AES_KEY_LENGTH, storage_widths[width_index]));

            for(size_t set = 0; set < app->num_key_sets; set++) {
                for(size_t slot = 0; slot < app->num_keys; slot++) {
                    uint8_t* key = dfc_credential_key_in_set(&credential, app, set, slot);
                    munit_assert_not_null(key);
                    memset(key, (int)(0x40 + set), storage_widths[width_index]);
                }
            }

            observed_wipe_count = 0;
            observed_wipe_length = 0;
            expected_secret_length = app->num_keys * storage_widths[width_index];
            expected_secret_byte = (uint8_t)(0x40 + rotations - 1);
            observed_secret = false;
            observed_zeroed_buffer = false;

            munit_assert_true(dfc_credential_roll_key_set(&credential, app, rotations));
            munit_assert_size(observed_wipe_count, ==, 1);
            munit_assert_size(observed_wipe_length, ==, DFC_MAX_KEYS * DFC_MAX_KEY_LEN);
            munit_assert_true(observed_secret);
            munit_assert_true(observed_zeroed_buffer);

            for(size_t slot = 0; slot < app->num_keys; slot++) {
                const uint8_t* active = dfc_credential_key_in_set_const(&credential, app, 0, slot);
                munit_assert_not_null(active);
                for(size_t i = 0; i < storage_widths[width_index]; i++) {
                    munit_assert_uint8(active[i], ==, (uint8_t)(0x40 + rotations));
                }
            }
        }
    }

    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/complete-scratch",
     test_roll_wipes_complete_scratch,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_roll_key_set_wipe",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
