#include "dfc_target_ffi.h"

#include <stdalign.h>
#include <string.h>

#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_virtual_picc.h"

#if !DFC_ENABLE_EMULATOR
#error "The target bridge requires the emulator role"
#endif

struct DfcTargetPicc {
    DfcCredential* credential;
    DfcVirtualPiccSession* session;
};

DfcTargetLayout dfc_target_credential_layout(void) {
    return (DfcTargetLayout){sizeof(DfcCredential), alignof(DfcCredential)};
}

void dfc_target_credential_init(void* storage) {
    if(storage) dfc_credential_clear(storage);
}

void dfc_target_credential_destroy(void* storage) {
    if(storage) dfc_secure_wipe(storage, sizeof(DfcCredential));
}

int32_t dfc_target_credential_decode(void* storage, const uint8_t* content, size_t len) {
    if(!storage) return DfcDerMalformed;
    return dfc_der_decode(storage, content, len);
}

int32_t dfc_target_credential_validate(const void* storage) {
    if(!storage) return DfcDerMalformed;
    return dfc_credential_validate_model(storage);
}

int32_t
    dfc_target_credential_encode(const void* storage, uint8_t* out, size_t capacity, size_t* len) {
    if(!storage || !len || (!out && capacity)) return DfcDerMalformed;
#if DFC_ENABLE_DER_ENCODER
    if(!out) return dfc_der_encoded_size(storage, len);
    return dfc_der_encode(storage, out, capacity, len);
#else
    (void)out;
    (void)capacity;
    return DfcDerUnsupported;
#endif
}

DfcTargetLayout dfc_target_picc_layout(void) {
    return (DfcTargetLayout){sizeof(DfcTargetPicc), alignof(DfcTargetPicc)};
}

int32_t dfc_target_picc_init(void* picc_storage, void* credential_storage, DfcTargetPicc** out) {
    if(!picc_storage || !credential_storage || !out) {
        return DfcVirtualPiccStatusProtocolError;
    }
    *out = NULL;
    DfcCredential* credential = credential_storage;
    if(dfc_credential_validate_model(credential) != DfcDerOk) {
        return DfcVirtualPiccStatusProtocolError;
    }
    DfcTargetPicc* picc = picc_storage;
    memset(picc, 0, sizeof(*picc));
    picc->credential = credential;
    picc->session = dfc_virtual_picc_session_alloc(credential);
    if(!picc->session) {
        dfc_secure_wipe(picc, sizeof(*picc));
        return DfcVirtualPiccStatusProtocolError;
    }
    *out = picc;
    return DfcVirtualPiccStatusOk;
}

void dfc_target_picc_destroy(DfcTargetPicc* picc) {
    if(!picc) return;
    if(picc->session) dfc_virtual_picc_session_free(picc->session);
    dfc_secure_wipe(picc, sizeof(*picc));
}

int32_t dfc_target_picc_activate(DfcTargetPicc* picc, DfcTargetActivation* out) {
    if(!picc || !out) return DfcVirtualPiccStatusProtocolError;
    DfcVirtualPiccActivation activation;
    DfcVirtualPiccStatus status = dfc_virtual_picc_scan_iso14443a(picc->session, &activation);
    memset(out, 0, sizeof(*out));
    if(status != DfcVirtualPiccStatusOk) return status;
    out->uid_len = activation.uid_len;
    out->ats_len = activation.ats_len;
    out->atqa_len = activation.atqa_len;
    out->protocol_len = activation.protocol_len;
    out->rf_detail_len = activation.rf_detail_len;
    memcpy(out->uid, activation.uid, activation.uid_len);
    memcpy(out->ats, activation.ats, activation.ats_len);
    memcpy(out->atqa, activation.atqa, activation.atqa_len);
    out->sak = activation.sak;
    memcpy(out->protocol, activation.protocol, activation.protocol_len);
    memcpy(out->rf_detail, activation.rf_detail, activation.rf_detail_len);
    return status;
}

int32_t dfc_target_picc_exchange(
    DfcTargetPicc* picc,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    if(!picc) return DfcVirtualPiccStatusProtocolError;
    return dfc_virtual_picc_iso_dep_exchange(
        picc->session, command, command_len, response, response_capacity, response_len);
}

int32_t dfc_target_picc_frame_exchange(
    DfcTargetPicc* picc,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    if(!picc) return DfcVirtualPiccStatusProtocolError;
    return dfc_virtual_picc_iso_dep_frame_exchange(
        picc->session, frame, frame_len, response, response_capacity, response_len);
}

int32_t dfc_target_picc_field_off(DfcTargetPicc* picc) {
    return picc ? dfc_virtual_picc_field_off(picc->session) : DfcVirtualPiccStatusProtocolError;
}

int32_t dfc_target_picc_reset_protocol(DfcTargetPicc* picc) {
    return picc ? dfc_virtual_picc_reset_protocol(picc->session) :
                  DfcVirtualPiccStatusProtocolError;
}

int32_t dfc_target_picc_advance_time(DfcTargetPicc* picc, uint32_t elapsed_milliseconds) {
    if(!picc) return DfcVirtualPiccStatusProtocolError;
    return dfc_virtual_picc_advance_time(picc->session, elapsed_milliseconds);
}

int32_t dfc_target_picc_snapshot(const DfcTargetPicc* picc, DfcTargetSnapshot* out) {
    if(!picc || !out) return DfcVirtualPiccStatusProtocolError;
    const DfcEmulator* emulator = picc->session->emulator;
    memset(out, 0, sizeof(*out));
    out->selected = (uint32_t)emulator->selected_application;
    out->selected_application_index = (uint32_t)emulator->selected_app_index;
    if(emulator->selected_application == DfcEmulatorSelectedApplicationApp &&
       emulator->selected_app_index < picc->credential->num_apps) {
        memcpy(out->selected_aid, picc->credential->apps[emulator->selected_app_index].aid, 3);
    }
    out->dirty = picc->credential->dirty;
    if(emulator->secure_messaging) {
        out->auth_mode = emulator->secure_messaging->cipher;
        out->auth_key_no = emulator->auth_key_no;
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    out->ev2_active = emulator->ev2_session_active;
    if(emulator->ev2_session_active) {
        out->ev2_key_no = emulator->ev2_authenticated_key_no;
        out->ev2_command_counter = emulator->ev2_command_counter;
    }
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    out->virtual_card_selected = emulator->virtual_card_selected;
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    out->proximity_verified = emulator->proximity_verified;
#endif
    return DfcVirtualPiccStatusOk;
}

int32_t dfc_target_picc_mark_persisted(DfcTargetPicc* picc) {
    if(!picc) return DfcVirtualPiccStatusProtocolError;
    dfc_credential_clear_dirty(picc->credential);
    return DfcVirtualPiccStatusOk;
}
