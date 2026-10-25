#ifndef DFC_FFI_INTERNAL_H
#define DFC_FFI_INTERNAL_H

#include "dfc_ffi.h"

#include "dfc_common.h"

static inline bool dfc_ffi_ranges_overlap(
    const void* first,
    size_t first_len,
    const void* second,
    size_t second_len) {
    if(first_len == 0 || second_len == 0) return false;
    if(!first || !second) return false;
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    if(first_len > UINTPTR_MAX - first_start || second_len > UINTPTR_MAX - second_start)
        return true;
    return first_start < second_start + second_len && second_start < first_start + first_len;
}

static inline void dfc_ffi_write_u16_le(uint8_t* out, uint16_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}

static inline void dfc_ffi_write_u32_le(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static inline void dfc_ffi_write_i32_le(uint8_t* out, int32_t value) {
    dfc_ffi_write_u32_le(out, (uint32_t)value);
}

#endif
