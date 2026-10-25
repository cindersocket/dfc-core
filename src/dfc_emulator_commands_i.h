#pragma once

#include "dfc_emulator_i.h"

#if DFC_ENABLE_EMULATOR

/* Private seams shared by the native command-family translation units. */
int32_t dfc_emulator_command_read_int32_le(const uint8_t* data);
bool dfc_emulator_command_is_authenticated_with_key(const DfcEmulator* emulator, uint8_t key_no);
bool dfc_emulator_command_is_authenticated_as_master(const DfcEmulator* emulator);
uint8_t dfc_emulator_command_current_key_settings_1(DfcEmulator* emulator);
uint8_t dfc_emulator_command_current_key_settings_2(DfcEmulator* emulator);
bool dfc_emulator_command_require_directory_access(DfcEmulator* emulator, DfcByteBuf* tx_buffer);
void dfc_emulator_command_apply_ev1_response_secure_messaging(
    DfcEmulator* emulator,
    uint8_t cmd,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_abort_transaction(DfcEmulator* emulator, DfcByteBuf* tx_buffer);
size_t dfc_emulator_command_unwrap_write_payload(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    size_t header_len,
    uint8_t comm,
    uint8_t* out,
    size_t out_cap);
void dfc_emulator_command_clear_pending_chain(DfcEmulator* emulator);
const uint8_t* dfc_emulator_command_auth_key(
    DfcEmulator* emulator,
    uint8_t key_no,
    uint8_t* factory,
    size_t factory_capacity,
    size_t* key_len);
bool dfc_emulator_command_picc_disabled_special_key(DfcEmulator* emulator, uint8_t key_no);
bool dfc_emulator_command_is_available_authentication_key(DfcEmulator* emulator, uint8_t key_no);
bool dfc_emulator_command_has_pending_additional_work(const DfcEmulator* emulator);
void dfc_emulator_command_get_key_settings(DfcEmulator* emulator, DfcByteBuf* tx_buffer);
void dfc_emulator_command_get_key_version(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_change_key(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_change_key_settings(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_set_configuration(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
#if DFC_ENABLE_KEY_SETS
void dfc_emulator_command_initialize_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_finalize_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_roll_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_change_key_ev2(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
#endif
void dfc_emulator_command_authenticate_step1(
    DfcEmulator* emulator,
    uint8_t cmd,
    const uint8_t* apdu,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_authenticate_step2(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    Dfc* dfc);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
bool dfc_emulator_command_authenticate_ev2_start(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    bool non_first,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_authenticate_ev2_continuation(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
#endif
void dfc_emulator_command_get_version(DfcEmulator* emulator, DfcByteBuf* tx_buffer);
void dfc_emulator_command_get_version_continuation(DfcEmulator* emulator, DfcByteBuf* tx_buffer);

#if DFC_ENABLE_STATIC_SIGNATURE
void dfc_emulator_command_read_signature(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
#endif

#if DFC_ENABLE_PROXIMITY_CHECK
bool dfc_emulator_command_prepare_proximity_check(DfcEmulator* emulator, DfcByteBuf* tx_buffer);
void dfc_emulator_command_proximity_check(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
void dfc_emulator_command_verify_proximity_check(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer);
#endif

#endif
