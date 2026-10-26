#include "dfc_ffi.h"

#include "dfc_an10922.h"

int32_t dfc_ffi_an10922_diversify(
    uint32_t algorithm,
    const uint8_t* master_key,
    size_t master_key_len,
    const uint8_t* diversification_input,
    size_t diversification_input_len,
    uint8_t* diversified_key,
    size_t diversified_key_capacity,
    size_t* diversified_key_len) {
    if(!diversified_key_len || algorithm > DFC_FFI_AN10922_TDEA3) return DFC_FFI_INVALID_ARGUMENT;
    size_t required = dfc_an10922_key_length((DfcAn10922Algorithm)algorithm);
    *diversified_key_len = required;
    if(!required || !master_key || !diversification_input || !diversified_key)
        return DFC_FFI_INVALID_ARGUMENT;
    if(diversified_key_capacity < required) return DFC_FFI_BUFFER_TOO_SMALL;
    return dfc_an10922_diversify(
               (DfcAn10922Algorithm)algorithm,
               master_key,
               master_key_len,
               diversification_input,
               diversification_input_len,
               diversified_key,
               diversified_key_capacity) ?
               DFC_FFI_OK :
               DFC_FFI_INVALID_ARGUMENT;
}
