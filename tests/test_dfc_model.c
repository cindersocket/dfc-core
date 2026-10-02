// Cross-codec properties and negative mutations for the credential model.

#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_text.h"

#include <string.h>

static void build_model(
    DfcCredential* credential,
    size_t uid_length,
    uint8_t picc_key_type,
    uint8_t app_key_type) {
    dfc_credential_clear(credential);
    credential->card.generation = DfcGenerationEv3;
    credential->card.storage = 8192;
    credential->uid_len = uid_length;
    for(size_t i = 0; i < uid_length; i++)
        credential->uid[i] = (uint8_t)(0x10 + i);

    credential->picc_key_settings_2 = picc_key_type | 2;
    size_t picc_key_length = dfc_credential_key_length(credential->picc_key_settings_2);
    munit_assert_true(dfc_credential_keys_resize(credential, NULL, 2, picc_key_length));
    for(size_t slot = 0; slot < 2; slot++) {
        uint8_t* key = dfc_credential_key(credential, NULL, slot);
        munit_assert_not_null(key);
        memset(key, (int)(0x20 + slot), dfc_credential_stored_key_length(picc_key_length));
    }

    const uint8_t aid[3] = {0x01, 0x00, 0x00};
    DfcApplication* app =
        dfc_credential_create_application_desfire_order(credential, aid, 0x0F, app_key_type | 2);
    munit_assert_not_null(app);
    app->has_iso_file_id = true;
    app->iso_file_id = 0x1001;
    for(size_t slot = 0; slot < app->num_keys; slot++) {
        uint8_t* key = dfc_credential_key(credential, app, slot);
        munit_assert_not_null(key);
        memset(key, (int)(0x40 + slot), dfc_credential_stored_key_length(app->key_len));
    }

    DfcFile* file = dfc_credential_create_file(credential, 0, 1);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_STANDARD_DATA;
    file->access_rights = 0xEEEE;
    file->has_iso_file_id = true;
    file->iso_file_id = 0x1002;
    file->declared_size = 4;
    file->contents_complete = true;
    munit_assert_true(dfc_file_resize(credential, file, 4));
    memcpy(dfc_file_data(credential, file), "\x01\x02\x03\x04", 4);
}

static void assert_round_trips(const DfcCredential* source) {
    static uint8_t binary[DFC_DER_MAX_SIZE];
    static uint8_t binary_again[DFC_DER_MAX_SIZE];
    static char text[DFC_TEXT_MAX_SIZE];
    static char text_again[DFC_TEXT_MAX_SIZE];
    static DfcCredential copy;
    static DfcCredential decoded;
    static DfcCredential parsed;
    DfcTextError detail = {0};
    size_t binary_length = 0;
    size_t binary_again_length = 0;
    size_t text_length = 0;
    size_t text_again_length = 0;

    munit_assert_int(dfc_credential_validate_model(source), ==, DfcModelOk);
    dfc_credential_copy_model(&copy, source);
    munit_assert_int(dfc_credential_validate_model(&copy), ==, DfcModelOk);

    munit_assert_int(dfc_der_encode(source, binary, sizeof(binary), &binary_length), ==, DfcDerOk);
    munit_assert_int(dfc_der_decode(&decoded, binary, binary_length), ==, DfcDerOk);
    munit_assert_int(
        dfc_der_encode(&decoded, binary_again, sizeof(binary_again), &binary_again_length),
        ==,
        DfcDerOk);
    munit_assert_size(binary_again_length, ==, binary_length);
    munit_assert_memory_equal(binary_length, binary_again, binary);

    munit_assert_int(dfc_text_write(source, text, sizeof(text), &text_length), ==, DfcTextOk);
    munit_assert_int(dfc_text_parse(&parsed, text, text_length, &detail), ==, DfcTextOk);
    munit_assert_int(
        dfc_text_write(&parsed, text_again, sizeof(text_again), &text_again_length),
        ==,
        DfcTextOk);
    munit_assert_size(text_again_length, ==, text_length);
    munit_assert_memory_equal(text_length, text_again, text);

    munit_assert_int(
        dfc_der_encode(&copy, binary_again, sizeof(binary_again), &binary_again_length),
        ==,
        DfcDerOk);
    munit_assert_size(binary_again_length, ==, binary_length);
    munit_assert_memory_equal(binary_length, binary_again, binary);

    munit_assert_int(
        dfc_der_encode(&parsed, binary_again, sizeof(binary_again), &binary_again_length),
        ==,
        DfcDerOk);
    munit_assert_size(binary_again_length, ==, binary_length);
    munit_assert_memory_equal(binary_length, binary_again, binary);

    munit_assert_int(
        dfc_text_write(&decoded, text_again, sizeof(text_again), &text_again_length),
        ==,
        DfcTextOk);
    munit_assert_size(text_again_length, ==, text_length);
    munit_assert_memory_equal(text_length, text_again, text);
}

static void assert_model_rejected(const DfcCredential* credential) {
    static uint8_t binary[DFC_DER_MAX_SIZE];
    static char text[DFC_TEXT_MAX_SIZE];
    size_t length = 0;
    munit_assert_int(dfc_credential_validate_model(credential), ==, DfcModelMalformed);
    munit_assert_int(
        dfc_der_encode(credential, binary, sizeof(binary), &length), ==, DfcDerMalformed);
    munit_assert_int(
        dfc_text_write(credential, text, sizeof(text), &length), ==, DfcTextMalformed);
}

static MunitResult test_valid_matrix(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const size_t uid_lengths[] = {
        DFC_DESFIRE_UID_SHORT_LEN, DFC_DESFIRE_UID_LEN, DFC_DESFIRE_UID_LONG_LEN};
    const uint8_t key_types[] = {DFC_KEY_TYPE_DES_2K3DES, DFC_KEY_TYPE_3K3DES, DFC_KEY_TYPE_AES};
    DfcCredential credential;
    for(size_t uid = 0; uid < sizeof(uid_lengths) / sizeof(uid_lengths[0]); uid++) {
        for(size_t picc = 0; picc < sizeof(key_types) / sizeof(key_types[0]); picc++) {
            for(size_t app = 0; app < sizeof(key_types) / sizeof(key_types[0]); app++) {
                build_model(&credential, uid_lengths[uid], key_types[picc], key_types[app]);
                assert_round_trips(&credential);
            }
        }
    }
    return MUNIT_OK;
}

#if DFC_ENABLE_KEY_SETS
static MunitResult test_mixed_key_set_matrix(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    const uint8_t active_types[] = {DFC_KEY_TYPE_AES, DFC_KEY_TYPE_3K3DES};
    const uint8_t set_types[][3] = {
        {DFC_KEY_SET_TYPE_AES, DFC_KEY_SET_TYPE_3K3DES, DFC_KEY_SET_TYPE_2K3DES},
        {DFC_KEY_SET_TYPE_3K3DES, DFC_KEY_SET_TYPE_AES, DFC_KEY_SET_TYPE_2K3DES},
    };
    for(size_t variant = 0; variant < 2; variant++) {
        DfcCredential credential;
        build_model(&credential, DFC_DESFIRE_UID_LEN, DFC_KEY_TYPE_AES, active_types[variant]);
        DfcApplication* app = &credential.apps[0];
        munit_assert_true(dfc_credential_key_sets_resize(
            &credential,
            app,
            3,
            2,
            dfc_credential_key_length(app->key_settings_2),
            DFC_KEY_SET_MAXIMUM_24_BYTE));
        for(size_t set = 0; set < 3; set++) {
            app->key_set_types[set] = set_types[variant][set];
            app->key_set_initialized[set] = true;
            size_t width = dfc_key_set_type_length(app->key_set_types[set]);
            for(size_t slot = 0; slot < app->num_keys; slot++) {
                uint8_t* key = dfc_credential_key_in_set(&credential, app, set, slot);
                munit_assert_not_null(key);
                memset(key, (int)(0x50 + set * 4 + slot), width);
            }
        }
        assert_round_trips(&credential);
    }
    return MUNIT_OK;
}
#endif

static MunitResult test_shared_primitive_boundaries(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    for(size_t length = 0; length <= DFC_DESFIRE_UID_MAX_LENGTH + 1; length++) {
        bool expected = length == DFC_DESFIRE_UID_SHORT_LEN || length == DFC_DESFIRE_UID_LEN ||
                        length == DFC_DESFIRE_UID_LONG_LEN;
        munit_assert_int(dfc_uid_length_is_valid(length), ==, expected);
    }
    const uint16_t reserved[] = {0x0000, 0x3F00, 0x3FFF, 0xFFFF};
    for(size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        munit_assert_true(dfc_iso_file_id_is_reserved(reserved[i]));
    }
    munit_assert_false(dfc_iso_file_id_is_reserved(0x0001));
    munit_assert_false(dfc_iso_file_id_is_reserved(0x3EFF));
    munit_assert_false(dfc_iso_file_id_is_reserved(0x3F01));
    munit_assert_false(dfc_iso_file_id_is_reserved(0xFFFE));
    for(unsigned type = 0; type <= UINT8_MAX; type++) {
        size_t expected =
            type == DFC_KEY_SET_TYPE_3K3DES ?
                24 :
                (type == DFC_KEY_SET_TYPE_2K3DES || type == DFC_KEY_SET_TYPE_AES ? 16 : 0);
        munit_assert_size(dfc_key_set_type_length((uint8_t)type), ==, expected);
    }
    return MUNIT_OK;
}

static MunitResult test_invalid_mutations(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;
    DfcCredential source;
    build_model(&source, DFC_DESFIRE_UID_LEN, DFC_KEY_TYPE_3K3DES, DFC_KEY_TYPE_AES);
    munit_assert_int(dfc_credential_validate_model(&source), ==, DfcModelOk);

    const uint16_t reserved[] = {0x0000, 0x3F00, 0x3FFF, 0xFFFF};
    for(size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        DfcCredential bad;
        dfc_credential_copy_model(&bad, &source);
        bad.apps[0].iso_file_id = reserved[i];
        assert_model_rejected(&bad);
        dfc_credential_copy_model(&bad, &source);
        bad.files[0].iso_file_id = reserved[i];
        assert_model_rejected(&bad);
    }

#if DFC_ENABLE_VIRTUAL_CARD
    const size_t invalid_uid_lengths[] = {0, 1, 3, 5, 6, 8, 9, 11};
    for(size_t i = 0; i < sizeof(invalid_uid_lengths) / sizeof(invalid_uid_lengths[0]); i++) {
        DfcCredential bad;
        dfc_credential_copy_model(&bad, &source);
        bad.virtual_card_configured = true;
        bad.virtual_card_uid_len = invalid_uid_lengths[i];
        assert_model_rejected(&bad);
    }
#endif

    DfcCredential bad;
    dfc_credential_copy_model(&bad, &source);
    bad.picc_key_pool_len--;
    assert_model_rejected(&bad);

    dfc_credential_copy_model(&bad, &source);
    bad.apps[0].key_offset = bad.picc_key_offset;
    assert_model_rejected(&bad);

    dfc_credential_copy_model(&bad, &source);
    bad.files[0].data_offset = bad.file_pool_used;
    assert_model_rejected(&bad);

    dfc_credential_copy_model(&bad, &source);
    bad.key_pool_used = DFC_KEY_POOL_SIZE + 1u;
    assert_model_rejected(&bad);

#if DFC_ENABLE_KEY_SETS
    dfc_credential_copy_model(&bad, &source);
    DfcApplication* app = &bad.apps[0];
    munit_assert_true(dfc_credential_key_sets_resize(&bad, app, 2, 2, 16, 24));
    app->key_set_types[0] = DFC_KEY_SET_TYPE_AES;
    app->key_set_types[1] = 0xFF;
    assert_model_rejected(&bad);
#endif
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/valid-matrix", test_valid_matrix, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if DFC_ENABLE_KEY_SETS
    {"/mixed-key-set-matrix", test_mixed_key_set_matrix, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/shared-primitive-boundaries",
     test_shared_primitive_boundaries,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/invalid-mutations", test_invalid_mutations, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_model",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
