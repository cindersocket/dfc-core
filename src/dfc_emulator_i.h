#pragma once

#include "dfc.h"
#include "dfc_emulator.h"

#define DFC_EMULATOR_TAG         "DfcEmulator"
#define DFC_ISO14443_4A_CID_MASK 0x08
#define DFC_ISO14443_4A_NAD_MASK 0x04

DfcApplication* dfc_emulator_current_app(DfcEmulator* emulator);
bool dfc_emulator_accepts_auth_cipher(DfcEmulator* emulator, uint8_t cipher);
static inline bool dfc_emulator_native_authentication_active(const DfcEmulator* emulator) {
    return emulator->auth_cipher != 0 && emulator->secure_messaging != NULL &&
           emulator->secure_messaging->cipher == emulator->auth_cipher;
}
size_t dfc_emulator_key_len(DfcEmulator* emulator);
size_t dfc_emulator_num_keys(DfcEmulator* emulator);
uint8_t* dfc_emulator_key(DfcEmulator* emulator, uint8_t key_no);
typedef enum {
    DfcFileAccessRead,
    DfcFileAccessWrite,
    DfcFileAccessReadWrite,
    DfcFileAccessChange,
} DfcFileAccess;

uint8_t dfc_emulator_file_effective_comm_settings(
    const DfcEmulator* emulator,
    const DfcFile* file,
    DfcFileAccess access,
    uint8_t configured_comm);
// For a command that any one of several rights can authorise (the value commands), the
// protection that applies. Measured on a genuine EV3
// (hardware_physical_ev3_2k_value_comm_modes.vec): when the session key matches one of those
// rights the file's configured mode applies; otherwise, if one of them is free, the command is
// plain. `read`, `write` and `rw` say which of the three rights can authorise this command.
uint8_t dfc_emulator_file_effective_comm_settings_for_rights(
    const DfcEmulator* emulator,
    const DfcFile* file,
    bool read,
    bool write,
    bool rw,
    uint8_t configured_comm);
bool dfc_emulator_file_access_allowed(
    const DfcEmulator* emulator,
    const DfcFile* file,
    DfcFileAccess access);
bool dfc_emulator_file_access_is_free(const DfcFile* file, DfcFileAccess access);
bool dfc_emulator_is_authenticated_with_key(const DfcEmulator* emulator, uint8_t key_no);
bool dfc_emulator_access_nibble_allows(const DfcEmulator* emulator, uint8_t nibble);
uint8_t* dfc_emulator_key_version(DfcEmulator* emulator, uint8_t key_no);
void dfc_emulator_discard_command_chain(DfcEmulator* emulator);
// End authentication and command state while preserving the open file transaction.
void dfc_emulator_retire_authentication(DfcEmulator* emulator);
void dfc_emulator_clear_iso_authentication(DfcEmulator* emulator);
// Wipe every pending-authentication secret without changing either protocol's
// phase or routing fields. Callers own those control-state transitions.
void dfc_emulator_clear_pending_authentication_storage(DfcEmulator* emulator);
bool dfc_emulator_abort_pending_native_work(DfcEmulator* emulator);
bool dfc_emulator_abort_transaction(DfcEmulator* emulator);
void dfc_emulator_publish_transaction(DfcEmulator* emulator);

#if DFC_ENABLE_SDM
typedef enum {
    DfcSdmRenderFailed,
    DfcSdmRenderRandomExhausted,
    DfcSdmRenderOk,
} DfcSdmRenderStatus;
typedef enum {
    DfcSdmReadFamilyNative = 1,
    DfcSdmReadFamilyNativeIsoDep,
    DfcSdmReadFamilyIso7816,
} DfcSdmReadFamily;
DfcSdmRenderStatus dfc_emulator_render_sdm_read_status(
    DfcEmulator* emulator,
    DfcFile* file,
    DfcSdmReadFamily family);
void dfc_emulator_retire_sdm_read_cache(DfcEmulator* emulator);
#endif

typedef enum {
    DfcEmulatorAuthFamilyNative,
    DfcEmulatorAuthFamilyEv2,
} DfcEmulatorAuthFamily;

void dfc_emulator_commit_auth_family(DfcEmulator* emulator, DfcEmulatorAuthFamily family);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
void dfc_emulator_discard_transaction_snapshot(DfcEmulator* emulator);
bool dfc_emulator_abort_transaction_snapshot(DfcEmulator* emulator);
bool dfc_emulator_transaction_snapshot_insert_file(DfcEmulator* emulator, size_t file_index);
void dfc_emulator_transaction_snapshot_delete_file(DfcEmulator* emulator, size_t file_index);
bool dfc_emulator_transaction_snapshot_capture_file(DfcEmulator* emulator, size_t file_index);
const uint8_t* dfc_emulator_transaction_snapshot_committed_data(
    const DfcEmulator* emulator,
    size_t file_index,
    bool* all_zero);
uint32_t dfc_emulator_transaction_snapshot_committed_record_count(
    const DfcEmulator* emulator,
    size_t file_index);
void dfc_emulator_transaction_snapshot_note_persistent_change(DfcEmulator* emulator);
bool dfc_emulator_transaction_snapshot_can_mirror_write(
    const DfcEmulator* emulator,
    size_t file_index,
    size_t offset,
    const uint8_t* data,
    size_t length);
bool dfc_emulator_transaction_snapshot_mirror_write(
    DfcEmulator* emulator,
    size_t file_index,
    size_t offset,
    const uint8_t* data,
    size_t length);
#else
static inline bool
    dfc_emulator_transaction_snapshot_insert_file(DfcEmulator* emulator, size_t file_index) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
    return true;
}
static inline void
    dfc_emulator_transaction_snapshot_delete_file(DfcEmulator* emulator, size_t file_index) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
}

static inline bool
    dfc_emulator_transaction_snapshot_capture_file(DfcEmulator* emulator, size_t file_index) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
    return true;
}

static inline const uint8_t* dfc_emulator_transaction_snapshot_committed_data(
    const DfcEmulator* emulator,
    size_t file_index,
    bool* all_zero) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
    if(all_zero) *all_zero = false;
    return NULL;
}

static inline uint32_t dfc_emulator_transaction_snapshot_committed_record_count(
    const DfcEmulator* emulator,
    size_t file_index) {
    if(!emulator || !emulator->credential || file_index >= emulator->credential->num_files)
        return 0;
    return emulator->credential->files[file_index].state.record.count;
}

static inline void
    dfc_emulator_transaction_snapshot_note_persistent_change(DfcEmulator* emulator) {
    DFC_UNUSED(emulator);
}
static inline bool dfc_emulator_transaction_snapshot_mirror_write(
    DfcEmulator* emulator,
    size_t file_index,
    size_t offset,
    const uint8_t* data,
    size_t length) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
    DFC_UNUSED(offset);
    DFC_UNUSED(data);
    DFC_UNUSED(length);
    return true;
}
static inline bool dfc_emulator_transaction_snapshot_can_mirror_write(
    const DfcEmulator* emulator,
    size_t file_index,
    size_t offset,
    const uint8_t* data,
    size_t length) {
    DFC_UNUSED(emulator);
    DFC_UNUSED(file_index);
    DFC_UNUSED(offset);
    DFC_UNUSED(data);
    DFC_UNUSED(length);
    return true;
}
#endif
void dfc_emulator_select_application(
    DfcEmulator* emulator,
    DfcEmulatorSelectedApplication selection,
    size_t app_index);

uint32_t dfc_emulator_read_uint24_le(const uint8_t* data);
bool dfc_emulator_d40_receive_plain(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* encrypted,
    size_t encrypted_len,
    uint8_t* plain);
uint8_t dfc_emulator_des_key_version(const uint8_t* key);

bool dfc_emulator_handle_iso7816_select(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    size_t prefix_len,
    bool* app_selected);

// Opt in to ISO response staging; the caller must deliver or wipe pending_chain.
bool dfc_emulator_handle_transport_command(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
// Reseal a natively-chained read answer under the EV2 session: emit_payload split
// the plaintext across `native` (first frame) + pending_chain, but an EV2 session
// must seal the whole answer once. Reassembles, seals, and re-chains the
// ciphertext so the ADDITIONAL_FRAME continuations serve sealed octets verbatim.
// Returns true when it resealed (the caller appends `native` as-is and does not
// protect again), false when there is no native chain pending.
bool dfc_emulator_ev2_reseal_native_chain(
    DfcEmulator* emulator,
    const uint8_t* clear_command,
    size_t clear_command_len,
    DfcByteBuf* native);

// Result of reassembling a reader->card native command chain under an EV2
// session (see dfc_emulator_ev2_reassemble_command_chain).
typedef enum {
    // Not a chained secured command: process `buffer` unchanged.
    DfcEv2RxChainNone,
    // More frames are expected; an ADDITIONAL_FRAME status was appended to the
    // caller's tx buffer and the caller must return now.
    DfcEv2RxChainPending,
    // The whole secured command was reassembled; *out_command/*out_command_len
    // point at emulator->command_chain for the envelope to verify and decrypt.
    DfcEv2RxChainComplete,
    // The chain was rejected; an error status was appended and the caller must
    // return now.
    DfcEv2RxChainError,
} DfcEv2RxChainResult;

// Join a reader->card native ADDITIONAL_FRAME command chain for a large
// enciphered WriteData/WriteRecord/UpdateRecord sent under an EV2 session (as a
// live multi-application terminal does). The EV2 envelope verifies the command MAC and
// decrypts over the WHOLE secured command, so the frames must be reassembled
// before dfc_ev2_prepare_command runs. On DfcEv2RxChainComplete the caller must,
// after preparing the command, discard the chain buffer and suppress a second
// chain-begin on the now-decrypted command (command_chain_expected = SIZE_MAX),
// exactly as dispatch_native_command does for the plaintext path.
DfcEv2RxChainResult dfc_emulator_ev2_reassemble_command_chain(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer,
    const uint8_t** out_command,
    size_t* out_command_len);
#endif
