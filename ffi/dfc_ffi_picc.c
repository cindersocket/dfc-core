#include "dfc_ffi_internal.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_der.h"
#include "dfc_port_ffi.h"

#if DFC_ENABLE_EMULATOR
#include "dfc_virtual_picc.h"

_Static_assert(
    DFC_FFI_PICC_BUFFER_TOO_SMALL == DfcVirtualPiccStatusBufferTooSmall,
    "FFI virtual-PICC status value drifted");

struct DfcFfiPicc {
    DfcFfiCredential* credential;
    DfcVirtualPiccSession* session;
    DfcFfiRandomCallback random;
    void* random_context;
};
#endif

// ---------------------------------------------------------- virtual PICC ---

#if DFC_ENABLE_EMULATOR
// Route the engine's randomness to this PICC for the rest of the call.
static void enter(const DfcFfiPicc* picc) {
    dfc_ffi_port_set_random(picc->random, picc->random_context);
}

static bool leave(void) {
    bool failed = dfc_ffi_port_random_failed();
    dfc_ffi_port_set_random(NULL, NULL);
    return failed;
}

int32_t dfc_ffi_picc_create(
    const DfcFfiCredential* credential,
    DfcFfiRandomCallback random,
    void* random_context,
    DfcFfiPicc** out) {
    if(!credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    DfcFfiCredential* copy = NULL;
    int32_t status = dfc_ffi_credential_clone(credential, &copy);
    if(status != DfcDerOk) return status;
    status = dfc_ffi_picc_create_take(&copy, random, random_context, out);
    dfc_ffi_credential_free(copy);
    return status;
}

int32_t dfc_ffi_picc_create_take(
    DfcFfiCredential** credential,
    DfcFfiRandomCallback random,
    void* random_context,
    DfcFfiPicc** out) {
    if(!credential || !*credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    *out = NULL;
    DfcModelStatus valid = dfc_credential_validate_model(&(*credential)->model);
    if(valid != DfcDerOk) return valid;
    DfcFfiPicc* picc = calloc(1, sizeof(*picc));
    if(!picc) return DFC_FFI_OUT_OF_MEMORY;
    picc->credential = *credential;
    picc->random = random;
    picc->random_context = random_context;
    enter(picc);
    picc->session = dfc_virtual_picc_session_alloc(&picc->credential->model);
    bool random_failed = leave();
    if(random_failed) {
        picc->credential = NULL;
        if(picc->session) dfc_virtual_picc_session_free(picc->session);
        free(picc);
        return DFC_FFI_RANDOM_FAILED;
    }
    if(!picc->session) {
        picc->credential = NULL;
        free(picc);
        return DFC_FFI_OUT_OF_MEMORY;
    }
    *credential = NULL;
    *out = picc;
    return DfcVirtualPiccStatusOk;
}

void dfc_ffi_picc_free(DfcFfiPicc* picc) {
    if(!picc) return;
    if(picc->session) dfc_virtual_picc_session_free(picc->session);
    dfc_ffi_credential_free(picc->credential);
    dfc_secure_wipe(picc, sizeof(*picc));
    free(picc);
}

int32_t dfc_ffi_picc_activate(DfcFfiPicc* picc, DfcFfiActivation* out) {
    if(!picc || !out) return DFC_FFI_INVALID_ARGUMENT;
    DfcVirtualPiccActivation activation;
    memset(&activation, 0, sizeof(activation));
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_scan_iso14443a(picc->session, &activation);
    bool random_failed = leave();
    memset(out, 0, sizeof(*out));
    if(random_failed) return DFC_FFI_RANDOM_FAILED;
    if(st != DfcVirtualPiccStatusOk) return st;
    out->uid_len = (uint32_t)activation.uid_len;
    memcpy(out->uid, activation.uid, activation.uid_len);
    out->ats_len = (uint32_t)activation.ats_len;
    memcpy(out->ats, activation.ats, activation.ats_len);
    out->atqa_len = (uint32_t)activation.atqa_len;
    memcpy(out->atqa, activation.atqa, activation.atqa_len);
    out->sak = activation.sak;
    out->protocol_len = (uint32_t)activation.protocol_len;
    memcpy(out->protocol, activation.protocol, activation.protocol_len);
    out->rf_detail_len = (uint32_t)activation.rf_detail_len;
    memcpy(out->rf_detail, activation.rf_detail, activation.rf_detail_len);
    return st;
}

int32_t dfc_ffi_picc_exchange(
    DfcFfiPicc* picc,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_cap,
    size_t* response_len) {
    if(!picc || !command || !response || !response_len) return DFC_FFI_INVALID_ARGUMENT;
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_iso_dep_exchange(
        picc->session, command, command_len, response, response_cap, response_len);
    bool random_failed = leave();
    if(random_failed) {
        *response_len = 0;
        return DFC_FFI_RANDOM_FAILED;
    }
    return st;
}

size_t dfc_ffi_picc_response_capacity(void) {
    return DFC_EMULATOR_CHAIN_BUFFER_SIZE;
}

int32_t dfc_ffi_picc_frame_exchange(
    DfcFfiPicc* picc,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* response,
    size_t response_cap,
    size_t* response_len) {
    if(!picc || !frame || !response || !response_len) return DFC_FFI_INVALID_ARGUMENT;
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_iso_dep_frame_exchange(
        picc->session, frame, frame_len, response, response_cap, response_len);
    bool random_failed = leave();
    if(random_failed) {
        *response_len = 0;
        return DFC_FFI_RANDOM_FAILED;
    }
    return st;
}

int32_t dfc_ffi_picc_field_off(DfcFfiPicc* picc) {
    if(!picc) return DFC_FFI_INVALID_ARGUMENT;
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_field_off(picc->session);
    bool random_failed = leave();
    if(random_failed) return DFC_FFI_RANDOM_FAILED;
    return st;
}

int32_t dfc_ffi_picc_reset_protocol(DfcFfiPicc* picc) {
    if(!picc) return DFC_FFI_INVALID_ARGUMENT;
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_reset_protocol(picc->session);
    bool random_failed = leave();
    if(random_failed) return DFC_FFI_RANDOM_FAILED;
    return st;
}

int32_t dfc_ffi_picc_advance_time(DfcFfiPicc* picc, uint32_t elapsed_milliseconds) {
    if(!picc) return DFC_FFI_INVALID_ARGUMENT;
    enter(picc);
    DfcVirtualPiccStatus st = dfc_virtual_picc_advance_time(picc->session, elapsed_milliseconds);
    bool random_failed = leave();
    if(random_failed) return DFC_FFI_RANDOM_FAILED;
    return st;
}

int32_t dfc_ffi_picc_snapshot(const DfcFfiPicc* picc, DfcFfiSnapshot* out) {
    if(!picc || !out) return DFC_FFI_INVALID_ARGUMENT;
    const DfcEmulator* e = picc->session->emulator;
    memset(out, 0, sizeof(*out));
    out->selected = (uint32_t)e->selected_application;
    out->selected_application_index = (uint32_t)e->selected_app_index;
    if(e->selected_application == DfcEmulatorSelectedApplicationApp &&
       e->selected_app_index < picc->credential->model.num_apps) {
        memcpy(out->selected_aid, picc->credential->model.apps[e->selected_app_index].aid, 3);
    }
    out->dirty = picc->credential->model.dirty;
    if(e->secure_messaging) {
        out->auth_mode = e->secure_messaging->cipher;
        out->auth_key_no = e->auth_key_no;
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    out->ev2_active = e->ev2_session_active;
    if(e->ev2_session_active) {
        out->ev2_key_no = e->ev2_authenticated_key_no;
        out->ev2_command_counter = e->ev2_command_counter;
    }
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    out->virtual_card_selected = e->virtual_card_selected;
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    out->proximity_verified = e->proximity_verified;
#endif
    return DfcVirtualPiccStatusOk;
}

int32_t dfc_ffi_picc_diagnostic_snapshot(const DfcFfiPicc* picc, DfcFfiDiagnosticSnapshot* out) {
    if(!out) return DFC_FFI_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if(!picc) return DFC_FFI_INVALID_ARGUMENT;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    const DfcEmulator* e = picc->session->emulator;
    if(e->ev2_session_active) {
        memcpy(out->transaction_identifier, e->ev2_transaction_identifier, 4);
        memcpy(out->encryption_key, e->ev2_session_encryption_key, 16);
        memcpy(out->mac_key, e->ev2_session_mac_key, 16);
    }
#endif
    return DfcVirtualPiccStatusOk;
}

int32_t dfc_ffi_picc_export(const DfcFfiPicc* picc, DfcFfiCredential** out) {
    if(!picc || !out) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_ffi_credential_clone(picc->credential, out);
}

int32_t dfc_ffi_picc_mark_persisted(DfcFfiPicc* picc) {
    if(!picc) return DFC_FFI_INVALID_ARGUMENT;
    dfc_credential_clear_dirty(&picc->credential->model);
    return DfcVirtualPiccStatusOk;
}
#else
int32_t dfc_ffi_picc_create(
    const DfcFfiCredential* credential,
    DfcFfiRandomCallback random,
    void* random_context,
    DfcFfiPicc** out) {
    DFC_UNUSED(credential);
    DFC_UNUSED(random);
    DFC_UNUSED(random_context);
    if(out) *out = NULL;
    return DFC_FFI_UNSUPPORTED;
}
int32_t dfc_ffi_picc_create_take(
    DfcFfiCredential** credential,
    DfcFfiRandomCallback random,
    void* random_context,
    DfcFfiPicc** out) {
    DFC_UNUSED(credential);
    DFC_UNUSED(random);
    DFC_UNUSED(random_context);
    if(out) *out = NULL;
    return DFC_FFI_UNSUPPORTED;
}
void dfc_ffi_picc_free(DfcFfiPicc* picc) {
    DFC_UNUSED(picc);
}
#endif
