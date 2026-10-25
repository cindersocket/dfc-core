#include "dfc_ffi_internal.h"

#include <string.h>

#include "dfc_response.h"

int32_t dfc_ffi_response_decode_version(
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_capacity) {
#if DFC_ENABLE_READER
    if(!out || out_capacity < DFC_FFI_RESPONSE_VERSION_SIZE)
        return DFC_FFI_RESPONSE_BUFFER_TOO_SMALL;
    memset(out, 0, DFC_FFI_RESPONSE_VERSION_SIZE);
    DfcResponseVersion decoded = {0};
    DfcResponseDecodeStatus status = dfc_response_decode_version(response, response_len, &decoded);
    if(status != DfcResponseDecodeOk) return status;
    const DfcResponseVersionPart* parts[] = {&decoded.hardware, &decoded.software};
    for(size_t i = 0; i < 2; i++) {
        size_t offset = i * 7;
        out[offset] = parts[i]->vendor_id;
        out[offset + 1] = parts[i]->type;
        out[offset + 2] = parts[i]->subtype;
        out[offset + 3] = parts[i]->major_version;
        out[offset + 4] = parts[i]->minor_version;
        out[offset + 5] = parts[i]->storage_size;
        out[offset + 6] = parts[i]->protocol;
    }
    memcpy(out + 14, decoded.uid, 7);
    memcpy(out + 21, decoded.batch_number, 5);
    out[26] = decoded.production_week;
    out[27] = decoded.production_year;
    return DFC_FFI_RESPONSE_OK;
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_capacity);
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_response_decode_application_ids(
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_capacity,
    size_t* out_len) {
#if DFC_ENABLE_READER
    if(!out_len || (!out && out_capacity)) return DFC_FFI_INVALID_ARGUMENT;
    size_t count = 0;
    DfcResponseDecodeStatus status = dfc_response_decode_application_ids(
        response, response_len, (uint8_t (*)[3])out, out_capacity / 3, &count);
    *out_len = count * 3;
    return status;
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_capacity);
    if(out_len) *out_len = 0;
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_response_decode_file_ids(
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_capacity,
    size_t* out_len) {
#if DFC_ENABLE_READER
    if(!out_len || (!out && out_capacity)) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_response_decode_file_ids(response, response_len, out, out_capacity, out_len);
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_capacity);
    if(out_len) *out_len = 0;
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}

static void ffi_pack_access(uint8_t* out, DfcResponseAccess access) {
    out[0] = (uint8_t)access.kind;
    out[1] = access.key_number;
}

int32_t dfc_ffi_response_decode_file_settings(
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_capacity) {
#if DFC_ENABLE_READER
    if(!out || out_capacity < DFC_FFI_RESPONSE_FILE_SETTINGS_SIZE)
        return DFC_FFI_RESPONSE_BUFFER_TOO_SMALL;
    memset(out, 0, DFC_FFI_RESPONSE_FILE_SETTINGS_SIZE);
    DfcResponseFileSettings decoded = {0};
    DfcResponseDecodeStatus status =
        dfc_response_decode_file_settings(response, response_len, &decoded);
    if(status != DfcResponseDecodeOk) return status;
    out[0] = decoded.type;
    out[1] = decoded.communication_mode;
    out[2] = decoded.sdm_enabled;
    dfc_ffi_write_u16_le(out + 4, decoded.access_rights_raw);
    ffi_pack_access(out + 6, decoded.access.read);
    ffi_pack_access(out + 8, decoded.access.write);
    ffi_pack_access(out + 10, decoded.access.read_write);
    ffi_pack_access(out + 12, decoded.access.change);
    if(decoded.type == DFC_FILE_TYPE_STANDARD_DATA || decoded.type == DFC_FILE_TYPE_BACKUP_DATA) {
        dfc_ffi_write_u32_le(out + 14, decoded.settings.data.size);
    } else if(decoded.type == DFC_FILE_TYPE_VALUE) {
        dfc_ffi_write_i32_le(out + 14, decoded.settings.value.lower_limit);
        dfc_ffi_write_i32_le(out + 18, decoded.settings.value.upper_limit);
        dfc_ffi_write_i32_le(out + 22, decoded.settings.value.limited_credit_value);
        out[26] = decoded.settings.value.limited_credit_enabled;
    } else {
        dfc_ffi_write_u32_le(out + 14, decoded.settings.records.record_size);
        dfc_ffi_write_u32_le(out + 18, decoded.settings.records.max_records);
        dfc_ffi_write_u32_le(out + 22, decoded.settings.records.current_records);
    }
    return DFC_FFI_RESPONSE_OK;
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_capacity);
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_response_decode_key_settings(
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_capacity) {
#if DFC_ENABLE_READER
    if(!out || out_capacity < DFC_FFI_RESPONSE_KEY_SETTINGS_SIZE)
        return DFC_FFI_RESPONSE_BUFFER_TOO_SMALL;
    memset(out, 0, DFC_FFI_RESPONSE_KEY_SETTINGS_SIZE);
    DfcResponseKeySettings decoded = {0};
    DfcResponseDecodeStatus status =
        dfc_response_decode_key_settings(response, response_len, &decoded);
    if(status != DfcResponseDecodeOk) return status;
    out[0] = decoded.settings_1;
    out[1] = decoded.settings_2;
    out[2] = decoded.key_type;
    out[3] = decoded.key_count;
    out[4] = decoded.has_key_set_settings;
    out[5] = decoded.active_key_set_version;
    out[6] = decoded.key_set_count;
    out[7] = decoded.max_key_size;
    out[8] = decoded.key_set_settings;
    return DFC_FFI_RESPONSE_OK;
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_capacity);
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_response_decode_key_version(
    const uint8_t* response,
    size_t response_len,
    uint8_t* key_version) {
#if DFC_ENABLE_READER
    return dfc_response_decode_key_version(response, response_len, key_version);
#else
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    if(key_version) *key_version = 0;
    return DFC_FFI_RESPONSE_UNSUPPORTED;
#endif
}
