#pragma once

#include <stddef.h>
#include <stdint.h>

// Compile this in each native boundary so a stale JNI build cannot borrow the
// linked core's answer and mistakenly declare itself compatible.
static inline uint64_t dfc_ffi_expected_layout_fingerprint(void) {
    uint64_t hash = UINT64_C(14695981039346656037);
    static const uint64_t words[] = {
#define DFC_FFI_LAYOUT_CONSTANT(name)     (uint64_t)(int64_t)(name),
#define DFC_FFI_LAYOUT_SIZE(type)         sizeof(type),
#define DFC_FFI_LAYOUT_FIELD(type, field) offsetof(type, field),
#include "dfc_ffi_layout.inc"
#undef DFC_FFI_LAYOUT_FIELD
#undef DFC_FFI_LAYOUT_SIZE
#undef DFC_FFI_LAYOUT_CONSTANT
    };
    for(size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        uint64_t value = words[i];
        for(size_t byte = 0; byte < sizeof(value); byte++) {
            hash ^= (uint8_t)(value >> (byte * 8));
            hash *= UINT64_C(1099511628211);
        }
    }
    return hash;
}
