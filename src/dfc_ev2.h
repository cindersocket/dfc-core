#pragma once

#include "dfc_emulator.h"

typedef enum {
    DfcEv2CommandPlain,
    DfcEv2CommandPlainCounted,
    DfcEv2CommandSecured,
    DfcEv2CommandFull,
    DfcEv2CommandInvalid,
} DfcEv2CommandSecurity;

DfcEv2CommandSecurity dfc_ev2_prepare_command(
    DfcEmulator* emulator,
    const uint8_t* command,
    size_t command_len,
    uint8_t* clear_command,
    size_t clear_capacity,
    size_t* clear_len);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
// Shared EV2 envelope core used by host and device transports. The adapters
// own framing and delivery retries; these functions own prepare, dispatch, and
// command-counter/session transitions so those rules cannot drift.
DfcEv2CommandSecurity dfc_emulator_ev2_prepare_secured_command(
    DfcEmulator* emulator,
    const uint8_t* secured_command,
    size_t secured_command_len,
    uint8_t* clear_command,
    size_t clear_capacity,
    size_t* clear_command_len,
    bool reassembled);

bool dfc_emulator_ev2_execute_prepared_command(
    DfcEmulator* emulator,
    DfcEv2CommandSecurity security,
    const uint8_t* clear_command,
    size_t clear_command_len,
    bool reassembled,
    DfcByteBuf* native_response,
    bool* handled);

bool dfc_emulator_ev2_should_protect_response(
    const DfcEmulator* emulator,
    DfcEv2CommandSecurity security);
#endif

// Protects a response directly in the caller's destination. `clear_response`
// may alias `secured_response`; partial overlap is supported. A cipher or MAC
// failure wipes any bytes staged in the destination, sets `secured_len` to
// zero, and terminates the EV2 session so the command cannot be replayed in it.
bool dfc_ev2_protect_response(
    DfcEmulator* emulator,
    const uint8_t* clear_command,
    size_t clear_command_len,
    const uint8_t* clear_response,
    size_t clear_response_len,
    uint8_t* secured_response,
    size_t secured_capacity,
    size_t* secured_len);

bool dfc_ev2_verify_chained_command_mac(
    const DfcEmulator* emulator,
    uint8_t instruction,
    const uint8_t* data,
    size_t data_len,
    const uint8_t mac[DFC_WIRE_MAC_LENGTH]);
