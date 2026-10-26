#include "dfc_ffi_internal.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_der.h"
#include "dfc_text.h"

// --------------------------------------------------------- credential I/O ---

int32_t dfc_ffi_credential_parse_text(
    const char* text,
    size_t len,
    DfcFfiCredential** out,
    DfcFfiError* error) {
    dfc_ffi_set_error(error, DfcDerOk, 0, NULL);
    if(!out || (!text && len)) {
        dfc_ffi_set_error(error, DFC_FFI_INVALID_ARGUMENT, 0, "invalid argument");
        return DFC_FFI_INVALID_ARGUMENT;
    }
    *out = NULL;
#if DFC_ENABLE_TEXT_CODEC
    DfcFfiCredential* credential = dfc_ffi_credential_alloc_uninitialized();
    if(!credential) return DFC_FFI_OUT_OF_MEMORY;
    DfcTextError detail = {0};
    DfcTextStatus st = dfc_text_parse(&credential->model, text, len, &detail);
    if(st != DfcTextOk) {
        dfc_ffi_set_error(error, st, (uint32_t)detail.line, detail.message);
        dfc_ffi_credential_free(credential);
        return st;
    }
    *out = credential;
    return DfcDerOk;
#else
    DFC_UNUSED(text);
    DFC_UNUSED(len);
    dfc_ffi_set_error(error, DFC_FFI_UNSUPPORTED, 0, "this build carries no text codec");
    return DFC_FFI_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_credential_decode(
    const uint8_t* dfcb,
    size_t len,
    DfcFfiCredential** out,
    DfcFfiError* error) {
    dfc_ffi_set_error(error, DfcDerOk, 0, NULL);
    if(!out || (!dfcb && len)) {
        dfc_ffi_set_error(error, DFC_FFI_INVALID_ARGUMENT, 0, "invalid argument");
        return DFC_FFI_INVALID_ARGUMENT;
    }
    *out = NULL;
    DfcFfiCredential* credential = dfc_ffi_credential_alloc_uninitialized();
    if(!credential) return DFC_FFI_OUT_OF_MEMORY;
    DfcDerStatus st = dfc_der_decode(&credential->model, dfcb, len);
    if(st != DfcDerOk) {
        dfc_ffi_set_error(error, st, 0, dfc_der_status_name(st));
        dfc_ffi_credential_free(credential);
        return st;
    }
    *out = credential;
    return DfcDerOk;
}

int32_t dfc_ffi_credential_load(
    const uint8_t* content,
    size_t len,
    DfcFfiCredential** out,
    DfcFfiError* error) {
    if(content && len > 0 && content[0] == DFC_DER_CREDENTIAL_TAG) {
        return dfc_ffi_credential_decode(content, len, out, error);
    }
    return dfc_ffi_credential_parse_text((const char*)content, len, out, error);
}

int32_t dfc_ffi_credential_encode(
    const DfcFfiCredential* credential,
    uint8_t* out,
    size_t cap,
    size_t* len) {
    if(!credential || !len || (!out && cap)) return DFC_FFI_INVALID_ARGUMENT;
#if DFC_ENABLE_DER_ENCODER
    if(!out) return dfc_der_encoded_size(&credential->model, len);
    DfcDerStatus st = dfc_der_encoded_size(&credential->model, len);
    if(st != DfcDerOk) return st;
    if(*len > cap) return DFC_FFI_BUFFER_TOO_SMALL;
    return dfc_der_encode(&credential->model, out, cap, len);
#else
    DFC_UNUSED(out);
    DFC_UNUSED(cap);
    return DFC_FFI_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_credential_write_text(
    const DfcFfiCredential* credential,
    char* out,
    size_t cap,
    size_t* len) {
    if(!credential || !len || (!out && cap)) return DFC_FFI_INVALID_ARGUMENT;
#if DFC_ENABLE_TEXT_CODEC
    DfcTextStatus st = dfc_text_write(&credential->model, out, cap, len);
    if(st == DfcTextCapacity && out) return DFC_FFI_BUFFER_TOO_SMALL;
    if(st == DfcTextCapacity && !out) return DfcDerOk;
    return st;
#else
    DFC_UNUSED(out);
    DFC_UNUSED(cap);
    return DFC_FFI_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_credential_validate(const DfcFfiCredential* credential) {
    if(!credential) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_credential_validate_model(&credential->model);
}

int32_t dfc_ffi_credential_clone(const DfcFfiCredential* credential, DfcFfiCredential** out) {
    if(!credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    *out = dfc_ffi_credential_alloc_uninitialized();
    if(!*out) return DFC_FFI_OUT_OF_MEMORY;
    dfc_credential_copy_model(&(*out)->model, &credential->model);
    return DfcDerOk;
}

void dfc_ffi_credential_free(DfcFfiCredential* credential) {
    if(!credential) return;
    dfc_secure_wipe(credential, sizeof(*credential));
    free(credential);
}
