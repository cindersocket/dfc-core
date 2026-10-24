#pragma once

// Allocation-neutral bridge for Rust and other freestanding runtimes.
//
// The caller owns storage for the credential. The virtual PICC borrows that
// credential and obtains its short-lived protocol objects through dfc_port.h,
// exactly like a native firmware integration. No hosted allocator is used.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DfcTargetPicc DfcTargetPicc;

typedef struct {
    size_t size;
    size_t alignment;
} DfcTargetLayout;

typedef struct {
    size_t uid_len;
    size_t ats_len;
    size_t atqa_len;
    size_t protocol_len;
    size_t rf_detail_len;
    uint8_t uid[10];
    uint8_t ats[20];
    uint8_t atqa[2];
    uint8_t sak;
    uint8_t protocol[2];
    uint8_t rf_detail[3];
} DfcTargetActivation;

typedef struct {
    uint32_t selected;
    uint32_t selected_application_index;
    uint32_t ev2_command_counter;
    uint8_t selected_aid[3];
    uint8_t dirty;
    uint8_t auth_mode;
    uint8_t auth_key_no;
    uint8_t ev2_active;
    uint8_t ev2_key_no;
    uint8_t ev2_transaction_identifier[4];
    uint8_t ev2_encryption_key[16];
    uint8_t ev2_mac_key[16];
    uint8_t virtual_card_selected;
    uint8_t proximity_verified;
} DfcTargetSnapshot;

DfcTargetLayout dfc_target_credential_layout(void);
void dfc_target_credential_init(void* storage);
void dfc_target_credential_destroy(void* storage);
int32_t dfc_target_credential_decode(void* storage, const uint8_t* content, size_t len);
int32_t dfc_target_credential_validate(const void* storage);
int32_t
    dfc_target_credential_encode(const void* storage, uint8_t* out, size_t capacity, size_t* len);

// The caller owns `picc_storage`; the PICC borrows `credential_storage` until
// destroyed. Keeping wrapper storage caller-owned leaves the firmware session
// allocation available for the protocol engine.
DfcTargetLayout dfc_target_picc_layout(void);
int32_t dfc_target_picc_init(void* picc_storage, void* credential_storage, DfcTargetPicc** out);
void dfc_target_picc_destroy(DfcTargetPicc* picc);
int32_t dfc_target_picc_activate(DfcTargetPicc* picc, DfcTargetActivation* out);
int32_t dfc_target_picc_exchange(
    DfcTargetPicc* picc,
    const uint8_t* command,
    size_t command_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len);
int32_t dfc_target_picc_frame_exchange(
    DfcTargetPicc* picc,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len);
int32_t dfc_target_picc_field_off(DfcTargetPicc* picc);
int32_t dfc_target_picc_reset_protocol(DfcTargetPicc* picc);
// A timer expiry rolls back pending writes and requires a fresh scan.
int32_t dfc_target_picc_advance_time(DfcTargetPicc* picc, uint32_t elapsed_milliseconds);
int32_t dfc_target_picc_snapshot(const DfcTargetPicc* picc, DfcTargetSnapshot* out);
int32_t dfc_target_picc_mark_persisted(DfcTargetPicc* picc);

#ifdef __cplusplus
}
#endif
