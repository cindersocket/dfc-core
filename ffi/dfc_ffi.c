#include "dfc_ffi_internal.h"
#include "dfc_ffi_layout.h"

#include <string.h>

#include "dfc_port_ffi.h"

#if !DFC_ENABLE_FFI
#error "Compile ffi/ with DFC_ENABLE_FFI=1"
#endif

// ------------------------------------------------------------ library ---

uint32_t dfc_ffi_abi_version(void) {
    return DFC_FFI_ABI_VERSION;
}

uint64_t dfc_ffi_layout_fingerprint(void) {
    uint64_t hash = dfc_ffi_expected_layout_fingerprint();
#if defined(DFC_FFI_TEST_LAYOUT_FINGERPRINT_XOR)
    hash ^= (uint64_t)DFC_FFI_TEST_LAYOUT_FINGERPRINT_XOR;
#endif
    return hash;
}

int32_t dfc_ffi_random_fill(uint8_t* out, size_t len) {
    if(len > 0 && !out) return DFC_FFI_INVALID_ARGUMENT;
    if(len > 0) dfc_ffi_port_system_random(out, len);
    return DFC_FFI_OK;
}

bool dfc_ffi_fixed_time_equal(const uint8_t* left, const uint8_t* right, size_t len) {
    if(len > 0 && (!left || !right)) return false;
    return dfc_ct_equal(left, right, len);
}

void dfc_ffi_secure_zero(void* buffer, size_t len) {
    if(buffer) dfc_secure_wipe(buffer, len);
}

void dfc_ffi_capabilities(DfcFfiCapabilities* out) {
    if(!out) return;
    memset(out, 0, sizeof(*out));
    DfcBuildCapabilities c = dfc_build_capabilities();
    out->abi_version = DFC_FFI_ABI_VERSION;
    out->build_role = DFC_BUILD_ROLE;
    out->build_profile = DFC_BUILD_PROFILE;
    out->generation_ev1 = c.generation_ev1;
    out->generation_ev2 = c.generation_ev2;
    out->generation_ev3 = c.generation_ev3;
    out->storage_2k = c.storage_2k;
    out->storage_4k = c.storage_4k;
    out->storage_8k = c.storage_8k;
    out->ev2_secure_messaging = c.ev2_secure_messaging;
    out->iso7816 = c.iso7816;
    out->transaction_mac = c.transaction_mac;
    out->secure_dynamic_messaging = c.secure_dynamic_messaging;
    out->proximity_check = c.proximity_check;
    out->virtual_card = c.virtual_card;
    out->key_sets = c.key_sets;
    out->delegated_applications = c.delegated_applications;
    out->transaction_timer = c.transaction_timer;
    out->application_capability_data = c.application_capability_data;
    out->static_signature = c.static_signature;
    out->auth_d40 = c.auth_d40;
    out->auth_iso = c.auth_iso;
    out->auth_aes = c.auth_aes;
    out->emulator = c.emulator;
    out->reader = c.reader;
    out->der_decoder = c.der_decoder;
    out->der_encoder = c.der_encoder;
    out->text_codec = c.text_codec;
    out->max_applications = DFC_MAX_APPS;
    out->max_files = DFC_MAX_FILES;
    out->max_keys = DFC_MAX_KEYS;
    out->file_pool_size = DFC_FILE_POOL_SIZE;
    out->key_pool_size = DFC_KEY_POOL_SIZE;
}

void dfc_ffi_struct_sizes(DfcFfiStructSizes* out) {
    if(!out) return;
    out->capabilities = sizeof(DfcFfiCapabilities);
    out->error = sizeof(DfcFfiError);
    out->card = sizeof(DfcFfiCard);
    out->picc = sizeof(DfcFfiPiccSettings);
    out->application = sizeof(DfcFfiApplication);
    out->file = sizeof(DfcFfiFile);
    out->key = sizeof(DfcFfiKey);
    out->activation = sizeof(DfcFfiActivation);
    out->snapshot = sizeof(DfcFfiSnapshot);
    out->diagnostic_snapshot = sizeof(DfcFfiDiagnosticSnapshot);
    out->reader_state = sizeof(DfcFfiReaderState);
}
