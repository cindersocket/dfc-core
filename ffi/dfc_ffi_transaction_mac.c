#include "dfc_ffi.h"

#include <stdlib.h>

#include "dfc_common.h"
#include "dfc_transaction_mac.h"

struct DfcFfiTransactionMacVerifier {
    DfcTransactionMacVerifier verifier;
    size_t allocation_size;
    uint8_t input[];
};

int32_t dfc_ffi_transaction_mac_verifier_new(
    size_t input_capacity,
    const uint8_t* key,
    const uint8_t* uid,
    size_t uid_len,
    uint32_t counter,
    DfcFfiTransactionMacVerifier** out) {
    if(!out) return DFC_FFI_INVALID_ARGUMENT;
    *out = NULL;
    if(!key || !uid || input_capacity == 0 ||
       input_capacity > SIZE_MAX - sizeof(DfcFfiTransactionMacVerifier))
        return DFC_FFI_INVALID_ARGUMENT;
    size_t allocation_size = sizeof(DfcFfiTransactionMacVerifier) + input_capacity;
    DfcFfiTransactionMacVerifier* context = calloc(1, allocation_size);
    if(!context) return DFC_FFI_OUT_OF_MEMORY;
    context->allocation_size = allocation_size;
    DfcTransactionMacStatus status = dfc_transaction_mac_verifier_init(
        &context->verifier, context->input, input_capacity, key, uid, uid_len, counter);
    if(status != DfcTransactionMacOk) {
        dfc_secure_wipe(context, allocation_size);
        free(context);
        return status;
    }
    *out = context;
    return DFC_FFI_TRANSACTION_MAC_OK;
}

void dfc_ffi_transaction_mac_verifier_free(DfcFfiTransactionMacVerifier* verifier) {
    if(!verifier) return;
    size_t allocation_size = verifier->allocation_size;
    dfc_transaction_mac_verifier_clear(&verifier->verifier);
    dfc_secure_wipe(verifier, allocation_size);
    free(verifier);
}

int32_t dfc_ffi_transaction_mac_add_data(
    DfcFfiTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_len) {
    if(!verifier) return DFC_FFI_TRANSACTION_MAC_INVALID;
    return dfc_transaction_mac_add_data(
        &verifier->verifier, command, file_number, offset, length, data, data_len);
}

int32_t dfc_ffi_transaction_mac_add_record_update(
    DfcFfiTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_len) {
    if(!verifier) return DFC_FFI_TRANSACTION_MAC_INVALID;
    return dfc_transaction_mac_add_record_update(
        &verifier->verifier, command, file_number, record_number, offset, length, data, data_len);
}

int32_t dfc_ffi_transaction_mac_add_value(
    DfcFfiTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t value) {
    if(!verifier) return DFC_FFI_TRANSACTION_MAC_INVALID;
    return dfc_transaction_mac_add_value(&verifier->verifier, command, file_number, value);
}

int32_t dfc_ffi_transaction_mac_add_clear_record(
    DfcFfiTransactionMacVerifier* verifier,
    uint8_t file_number) {
    if(!verifier) return DFC_FFI_TRANSACTION_MAC_INVALID;
    return dfc_transaction_mac_add_clear_record(&verifier->verifier, file_number);
}

int32_t dfc_ffi_transaction_mac_add_reader_id(
    DfcFfiTransactionMacVerifier* verifier,
    const uint8_t* current_reader_id,
    const uint8_t* encrypted_previous_reader_id) {
    if(!verifier) return DFC_FFI_TRANSACTION_MAC_INVALID;
    return dfc_transaction_mac_add_reader_id(
        &verifier->verifier, current_reader_id, encrypted_previous_reader_id);
}

int32_t dfc_ffi_transaction_mac_verify(
    const DfcFfiTransactionMacVerifier* verifier,
    const uint8_t* mac,
    uint8_t* verified) {
    if(verified) *verified = 0;
    if(!verifier || !verified) return DFC_FFI_TRANSACTION_MAC_INVALID;
    bool result = false;
    DfcTransactionMacStatus status = dfc_transaction_mac_verify(&verifier->verifier, mac, &result);
    *verified = result;
    return status;
}
