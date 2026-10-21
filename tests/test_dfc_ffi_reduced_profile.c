#include "dfc_ffi.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dfc_common.h"
#include "dfc_der.h"

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if(!(condition)) {                                                                  \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                                       \
        }                                                                                   \
    } while(0)

static int rejected_application_does_not_consume_keys(
    const DfcFfiCapabilities* capabilities,
    uint8_t unsupported_feature) {
    DfcFfiCredential* credential = NULL;
    CHECK(dfc_ffi_credential_new(&credential) == DFC_FFI_OK);

    DfcFfiApplication application = {0};
    application.aid[0] = 0x11;
    application.aid[1] = unsupported_feature;
    application.aid[2] = 0x01;
    application.num_keys = capabilities->max_keys;
    application.key_len = 24;
    application.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_3K3DES | capabilities->max_keys);
    if(unsupported_feature == 1) {
        application.num_key_sets = 2;
        application.key_set_max_size = 24;
    } else if(unsupported_feature == 2) {
        application.has_capability_data = 1;
    } else {
        application.delegated = 1;
    }

    size_t allocation = (size_t)capabilities->max_keys * 24;
    CHECK(allocation > 0);
    size_t attempts = capabilities->key_pool_size / allocation + 2;
    for(size_t i = 0; i < attempts; i++) {
        uint32_t index = UINT32_C(0xA5A5A5A5);
        CHECK(
            dfc_ffi_credential_add_application(credential, &application, &index) ==
            DfcDerUnsupported);
        CHECK(index == UINT32_C(0xA5A5A5A5));
        CHECK(dfc_ffi_credential_application_count(credential) == 0);
    }

    application.num_key_sets = 0;
    application.key_set_max_size = 0;
    application.has_capability_data = 0;
    application.delegated = 0;
    uint32_t index = UINT32_MAX;
    CHECK(dfc_ffi_credential_add_application(credential, &application, &index) == DFC_FFI_OK);
    CHECK(index == 0);
    CHECK(dfc_ffi_credential_application_count(credential) == 1);

    dfc_ffi_credential_free(credential);
    return 0;
}

int main(void) {
    DfcFfiCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    dfc_ffi_capabilities(&capabilities);
    CHECK(!capabilities.key_sets);
    CHECK(!capabilities.application_capability_data);
    CHECK(!capabilities.delegated_applications);
    CHECK(!capabilities.static_signature);
    CHECK(!capabilities.ev2_secure_messaging);
    CHECK(!capabilities.proximity_check);
    CHECK(!capabilities.virtual_card);
    CHECK(!capabilities.secure_dynamic_messaging);
    CHECK(!capabilities.transaction_mac);

    DfcFfiCredential* credential = NULL;
    CHECK(dfc_ffi_credential_new(&credential) == DFC_FFI_OK);

    DfcFfiCard card = {0};
    card.generation = DfcGenerationEv1;
    card.uid_len = 7;
    memset(card.uid, 0x11, card.uid_len);
    CHECK(dfc_ffi_credential_set_card(credential, &card) == DFC_FFI_OK);
    DfcFfiCard card_before;
    DfcFfiCard card_after;
    CHECK(dfc_ffi_credential_get_card(credential, &card_before) == DFC_FFI_OK);
    DfcFfiCard rejected_card = card;
    rejected_card.storage = DfcStorage8KByteCount;
    rejected_card.uid[0] = 0xEE;
    rejected_card.has_static_signature = 1;
    memset(rejected_card.static_signature, 0xA5, sizeof(rejected_card.static_signature));
    CHECK(dfc_ffi_credential_set_card(credential, &rejected_card) == DfcDerUnsupported);
    CHECK(dfc_ffi_credential_get_card(credential, &card_after) == DFC_FFI_OK);
    CHECK(memcmp(&card_before, &card_after, sizeof(card_before)) == 0);

    DfcFfiPiccSettings picc = {0};
    picc.num_keys = 1;
    picc.key_len = 16;
    picc.key_settings_1 = 0x0F;
    picc.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_AES | 1);
    CHECK(dfc_ffi_credential_set_picc(credential, &picc) == DFC_FFI_OK);
    DfcFfiKey picc_key = {.len = 16, .version = 0x42};
    memset(picc_key.value, 0x5A, picc_key.len);
    CHECK(
        dfc_ffi_credential_set_key(credential, DFC_FFI_OWNER_PICC, 0, 0, &picc_key) == DFC_FFI_OK);
    DfcFfiPiccSettings picc_before;
    DfcFfiPiccSettings picc_after;
    CHECK(dfc_ffi_credential_get_picc(credential, &picc_before) == DFC_FFI_OK);

    for(unsigned int feature = 0; feature < 4; feature++) {
        DfcFfiPiccSettings rejected_picc = picc;
        rejected_picc.key_settings_1 = (uint8_t)(0x20 + feature);
        if(feature == 0) {
            rejected_picc.has_ev2_capabilities = 1;
        } else if(feature == 1) {
            rejected_picc.has_proximity_key = 1;
        } else if(feature == 2) {
            rejected_picc.virtual_card_configured = 1;
            rejected_picc.virtual_card_installation_id_len = 1;
            rejected_picc.virtual_card_uid_len = 7;
        } else {
            rejected_picc.has_dam_keys = 1;
        }
        CHECK(dfc_ffi_credential_set_picc(credential, &rejected_picc) == DfcDerUnsupported);
        CHECK(dfc_ffi_credential_get_picc(credential, &picc_after) == DFC_FFI_OK);
        CHECK(memcmp(&picc_before, &picc_after, sizeof(picc_before)) == 0);
        DfcFfiKey key_after;
        CHECK(
            dfc_ffi_credential_get_key(credential, DFC_FFI_OWNER_PICC, 0, 0, &key_after) ==
            DFC_FFI_OK);
        CHECK(memcmp(&picc_key, &key_after, sizeof(picc_key)) == 0);
    }

    DfcFfiApplication application = {0};
    application.aid[0] = 0x01;
    application.aid[1] = 0x02;
    application.aid[2] = 0x03;
    application.num_keys = 1;
    application.key_len = 16;
    application.key_settings_2 = (uint8_t)(DFC_KEY_TYPE_AES | 1);
    uint32_t application_index = UINT32_MAX;
    CHECK(
        dfc_ffi_credential_add_application(credential, &application, &application_index) ==
        DFC_FFI_OK);
    CHECK(application_index == 0);
    DfcFfiApplication application_before;
    DfcFfiApplication application_after;
    CHECK(dfc_ffi_credential_get_application(credential, 0, &application_before) == DFC_FFI_OK);

    DfcFfiFile file = {0};
    file.owner = 0;
    file.number = 1;
    file.type = DFC_FILE_TYPE_STANDARD_DATA;
    file.declared_size = 16;
    uint32_t file_index = UINT32_MAX;
    CHECK(dfc_ffi_credential_add_file(credential, &file, &file_index) == DFC_FFI_OK);
    CHECK(file_index == 0);
    DfcFfiFile file_before;
    DfcFfiFile file_after;
    CHECK(dfc_ffi_credential_get_file(credential, 0, &file_before) == DFC_FFI_OK);

    DfcFfiFile rejected_file = file;
    rejected_file.number = 2;
    rejected_file.sdm_enabled = 1;
    uint32_t rejected_index = UINT32_C(0xA5A5A5A5);
    CHECK(
        dfc_ffi_credential_add_file(credential, &rejected_file, &rejected_index) ==
        DfcDerUnsupported);
    CHECK(rejected_index == UINT32_C(0xA5A5A5A5));
    CHECK(dfc_ffi_credential_file_count(credential) == 1);
    CHECK(dfc_ffi_credential_get_file(credential, 0, &file_after) == DFC_FFI_OK);
    CHECK(memcmp(&file_before, &file_after, sizeof(file_before)) == 0);

    rejected_file = file;
    rejected_file.number = 3;
    rejected_file.type = DFC_FILE_TYPE_TRANSACTION_MAC;
    rejected_index = UINT32_C(0xA5A5A5A5);
    CHECK(
        dfc_ffi_credential_add_file(credential, &rejected_file, &rejected_index) ==
        DfcDerUnsupported);
    CHECK(rejected_index == UINT32_C(0xA5A5A5A5));
    CHECK(dfc_ffi_credential_file_count(credential) == 1);
    CHECK(dfc_ffi_credential_get_file(credential, 0, &file_after) == DFC_FFI_OK);
    CHECK(memcmp(&file_before, &file_after, sizeof(file_before)) == 0);
    CHECK(dfc_ffi_credential_get_application(credential, 0, &application_after) == DFC_FFI_OK);
    CHECK(memcmp(&application_before, &application_after, sizeof(application_before)) == 0);

    dfc_ffi_credential_free(credential);

    CHECK(rejected_application_does_not_consume_keys(&capabilities, 1) == 0);
    CHECK(rejected_application_does_not_consume_keys(&capabilities, 2) == 0);
    CHECK(rejected_application_does_not_consume_keys(&capabilities, 3) == 0);
    return 0;
}
