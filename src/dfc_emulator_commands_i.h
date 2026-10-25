#pragma once

#include "dfc_emulator_i.h"

#if DFC_ENABLE_EMULATOR

/* Private seams shared by the native command-family translation units. */
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
