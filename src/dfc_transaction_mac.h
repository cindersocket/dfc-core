#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dfc_common.h"

typedef enum {
    DfcTransactionMacOk = 0,
    DfcTransactionMacInvalid,
    DfcTransactionMacCapacity,
    DfcTransactionMacCryptoFailed,
} DfcTransactionMacStatus;

#define DFC_TRANSACTION_MAC_UID_MAX_LENGTH 7u

typedef struct {
    uint8_t* input;
    size_t input_length;
    size_t input_capacity;
    uint8_t key[DFC_AES_KEY_LENGTH];
    uint8_t uid[DFC_TRANSACTION_MAC_UID_MAX_LENGTH];
    size_t uid_length;
    uint32_t counter;
    uint32_t lifecycle_cookie;
    bool initialized;
} DfcTransactionMacVerifier;

// The caller owns `input` and chooses its capacity. Init accepts uninitialized
// verifier storage and overwrites it. Clear an initialized verifier before
// reinitializing when its accumulated input must also be wiped.
DfcTransactionMacStatus dfc_transaction_mac_verifier_init(
    DfcTransactionMacVerifier* verifier,
    uint8_t* input,
    size_t input_capacity,
    const uint8_t key[DFC_AES_KEY_LENGTH],
    const uint8_t* uid,
    size_t uid_length,
    uint32_t counter);

void dfc_transaction_mac_verifier_clear(DfcTransactionMacVerifier* verifier);

DfcTransactionMacStatus dfc_transaction_mac_add_data(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length);

DfcTransactionMacStatus dfc_transaction_mac_add_record_update(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length);

DfcTransactionMacStatus dfc_transaction_mac_add_value(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t value);

DfcTransactionMacStatus
    dfc_transaction_mac_add_clear_record(DfcTransactionMacVerifier* verifier, uint8_t file_number);

DfcTransactionMacStatus dfc_transaction_mac_add_reader_id(
    DfcTransactionMacVerifier* verifier,
    const uint8_t current_reader_id[DFC_TRANSACTION_READER_ID_LENGTH],
    const uint8_t encrypted_previous_reader_id[DFC_TRANSACTION_READER_ID_LENGTH]);

DfcTransactionMacStatus dfc_transaction_mac_verify(
    const DfcTransactionMacVerifier* verifier,
    const uint8_t mac[DFC_WIRE_MAC_LENGTH],
    bool* verified);
