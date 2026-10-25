#include "dfc_ffi_internal.h"

#include <string.h>

#include "dfc_sdm.h"

int32_t dfc_ffi_sdm_verify_ascii(
    const uint8_t* message,
    size_t message_len,
    uint32_t fields,
    size_t plain_uid_offset,
    size_t plain_uid_len,
    size_t plain_read_counter_offset,
    size_t encrypted_picc_data_offset,
    size_t encrypted_picc_data_len,
    size_t encrypted_file_data_offset,
    size_t encrypted_file_data_len,
    size_t mac_input_offset,
    size_t mac_offset,
    const uint8_t* meta_read_key,
    const uint8_t* file_read_key,
    uint8_t* decrypted_file_data,
    size_t decrypted_file_data_capacity,
    size_t* required_decrypted_file_data_len,
    uint8_t* result,
    size_t result_capacity) {
    if(!result || result_capacity < DFC_FFI_SDM_RESULT_SIZE) return DFC_FFI_BUFFER_TOO_SMALL;
    if((decrypted_file_data_capacity != 0 && !decrypted_file_data) ||
       dfc_ffi_ranges_overlap(message, message_len, result, DFC_FFI_SDM_RESULT_SIZE) ||
       dfc_ffi_ranges_overlap(
           message, message_len, decrypted_file_data, decrypted_file_data_capacity) ||
       dfc_ffi_ranges_overlap(
           result, DFC_FFI_SDM_RESULT_SIZE, decrypted_file_data, decrypted_file_data_capacity))
        return DFC_FFI_INVALID_ARGUMENT;
    memset(result, 0, DFC_FFI_SDM_RESULT_SIZE);
    if(decrypted_file_data && decrypted_file_data_capacity != 0)
        memset(decrypted_file_data, 0, decrypted_file_data_capacity);
    if(!required_decrypted_file_data_len) return DFC_FFI_INVALID_ARGUMENT;
    DfcSdmVerifyConfig config = {
        .plain_uid_length = plain_uid_len,
        .plain_uid = {(fields & DFC_FFI_SDM_PLAIN_UID) != 0, plain_uid_offset},
        .plain_read_counter =
            {(fields & DFC_FFI_SDM_PLAIN_READ_COUNTER) != 0, plain_read_counter_offset},
        .encrypted_picc_data =
            {(fields & DFC_FFI_SDM_ENCRYPTED_PICC_DATA) != 0, encrypted_picc_data_offset},
        .encrypted_picc_data_length = encrypted_picc_data_len,
        .encrypted_file_data =
            {(fields & DFC_FFI_SDM_ENCRYPTED_FILE_DATA) != 0, encrypted_file_data_offset},
        .encrypted_file_data_length = encrypted_file_data_len,
        .mac_input_offset = mac_input_offset,
        .mac_offset = mac_offset,
    };
    DfcSdmVerifyResult decoded = {0};
    DfcSdmVerifyStatus status = dfc_sdm_verify_ascii(
        message,
        message_len,
        &config,
        meta_read_key,
        file_read_key,
        decrypted_file_data,
        decrypted_file_data_capacity,
        required_decrypted_file_data_len,
        &decoded);
    if(status == DfcSdmVerifyOk) {
        result[0] = decoded.has_uid;
        result[1] = (uint8_t)decoded.uid_length;
        memcpy(result + 2, decoded.uid, sizeof(decoded.uid));
        result[12] = decoded.has_read_counter;
        dfc_ffi_write_u32_le(result + 16, decoded.read_counter);
    }
    dfc_secure_wipe(&decoded, sizeof(decoded));
    return status;
}
