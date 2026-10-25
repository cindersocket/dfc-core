#include "dfc_transaction_mac.h"

#include "aes_cmac.h"
#include "dfc_transaction_mac_i.h"
#include "dfc_port.h"

#include <string.h>

#define TRANSACTION_BLOCK_SIZE      16u
#define TRANSACTION_VERIFIER_COOKIE 0x544D4143u

enum {
    TransactionDataHeaderLength = 8,
    TransactionRecordUpdateHeaderLength = 11,
    TransactionValueHeaderLength = 6,
    TransactionClearRecordHeaderLength = 2,
    TransactionReaderIdHeaderLength = 1 + DFC_TRANSACTION_READER_ID_LENGTH,
};

static bool uint24_is_valid(uint32_t value) {
    return value <= 0xFFFFFFu;
}

static bool verifier_is_valid(const DfcTransactionMacVerifier* verifier) {
    return verifier && verifier->lifecycle_cookie == TRANSACTION_VERIFIER_COOKIE &&
           verifier->initialized && verifier->input &&
           verifier->input_length <= verifier->input_capacity;
}

static bool append_entry(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    const uint8_t* header,
    size_t header_length,
    const uint8_t* data,
    size_t data_length) {
    if(!input || !input_length || !header || (data_length && !data) ||
       *input_length > input_capacity)
        return false;
    size_t header_padding =
        (TRANSACTION_BLOCK_SIZE - header_length % TRANSACTION_BLOCK_SIZE) % TRANSACTION_BLOCK_SIZE;
    size_t data_padding =
        (TRANSACTION_BLOCK_SIZE - data_length % TRANSACTION_BLOCK_SIZE) % TRANSACTION_BLOCK_SIZE;
    if(header_length > SIZE_MAX - header_padding ||
       header_length + header_padding > SIZE_MAX - data_length ||
       header_length + header_padding + data_length > SIZE_MAX - data_padding)
        return false;
    size_t entry_length = header_length + header_padding + data_length + data_padding;
    if(entry_length > input_capacity - *input_length) return false;

    size_t offset = *input_length;
    memcpy(input + offset, header, header_length);
    offset += header_length;
    memset(input + offset, 0, header_padding);
    offset += header_padding;
    if(data_length) memcpy(input + offset, data, data_length);
    offset += data_length;
    memset(input + offset, 0, data_padding);
    *input_length += entry_length;
    return true;
}

static bool input_has_capacity(
    size_t input_capacity,
    size_t input_length,
    size_t header_length,
    size_t data_length) {
    if(input_length > input_capacity) return false;
    size_t header_padding =
        (TRANSACTION_BLOCK_SIZE - header_length % TRANSACTION_BLOCK_SIZE) % TRANSACTION_BLOCK_SIZE;
    size_t data_padding =
        (TRANSACTION_BLOCK_SIZE - data_length % TRANSACTION_BLOCK_SIZE) % TRANSACTION_BLOCK_SIZE;
    if(header_length > SIZE_MAX - header_padding ||
       header_length + header_padding > SIZE_MAX - data_length ||
       header_length + header_padding + data_length > SIZE_MAX - data_padding)
        return false;
    return header_length + header_padding + data_length + data_padding <=
           input_capacity - input_length;
}

bool dfc_transaction_mac_input_can_add_data(
    size_t input_capacity,
    size_t input_length,
    size_t data_length) {
    return input_has_capacity(
        input_capacity, input_length, TransactionDataHeaderLength, data_length);
}

bool dfc_transaction_mac_input_can_add_record_update(
    size_t input_capacity,
    size_t input_length,
    size_t data_length) {
    return input_has_capacity(
        input_capacity, input_length, TransactionRecordUpdateHeaderLength, data_length);
}

bool dfc_transaction_mac_input_can_add_value(size_t input_capacity, size_t input_length) {
    return input_has_capacity(input_capacity, input_length, TransactionValueHeaderLength, 0);
}

bool dfc_transaction_mac_input_can_add_clear_record(size_t input_capacity, size_t input_length) {
    return input_has_capacity(input_capacity, input_length, TransactionClearRecordHeaderLength, 0);
}

bool dfc_transaction_mac_input_can_add_reader_id(
    size_t input_capacity,
    size_t input_length,
    bool authenticated) {
    return input_has_capacity(
        input_capacity,
        input_length,
        TransactionReaderIdHeaderLength,
        authenticated ? DFC_TRANSACTION_READER_ID_LENGTH : 0);
}

static void write_uint24_le(uint8_t output[3], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
}

static void write_uint32_le(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

DfcTransactionMacStatus dfc_transaction_mac_verifier_init(
    DfcTransactionMacVerifier* verifier,
    uint8_t* input,
    size_t input_capacity,
    const uint8_t key[DFC_AES_KEY_LENGTH],
    const uint8_t* uid,
    size_t uid_length,
    uint32_t counter) {
    if(!verifier) return DfcTransactionMacInvalid;
    // The public object may be uninitialized storage. Never inspect a prior
    // pointer here; callers that need input wiping clear an initialized object first.
    dfc_secure_wipe(verifier, sizeof(*verifier));
    if(!input || input_capacity == 0 || !key || !uid || counter == 0 ||
       (uid_length != DFC_DESFIRE_UID_SHORT_LEN &&
        uid_length != DFC_TRANSACTION_MAC_UID_MAX_LENGTH))
        return DfcTransactionMacInvalid;
    verifier->input = input;
    verifier->input_capacity = input_capacity;
    memcpy(verifier->key, key, sizeof(verifier->key));
    memcpy(verifier->uid, uid, uid_length);
    verifier->uid_length = uid_length;
    verifier->counter = counter;
    verifier->lifecycle_cookie = TRANSACTION_VERIFIER_COOKIE;
    verifier->initialized = true;
    return DfcTransactionMacOk;
}

void dfc_transaction_mac_verifier_clear(DfcTransactionMacVerifier* verifier) {
    if(!verifier) return;
    if(verifier->input && verifier->input_length <= verifier->input_capacity)
        dfc_secure_wipe(verifier->input, verifier->input_length);
    dfc_secure_wipe(verifier, sizeof(*verifier));
}

DfcTransactionMacStatus dfc_transaction_mac_add_data(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!verifier_is_valid(verifier) || !uint24_is_valid(offset) || !uint24_is_valid(length) ||
       (data_length && !data))
        return DfcTransactionMacInvalid;
    switch(command) {
    case DFC_CMD_READ_DATA:
    case DFC_CMD_WRITE_DATA:
        if(data_length != length) return DfcTransactionMacInvalid;
        break;
    case DFC_CMD_READ_RECORDS:
    case DFC_CMD_READ_RECORDS_ISO:
        break;
    case DFC_CMD_WRITE_RECORD:
    case DFC_CMD_WRITE_RECORD_ISO:
        if(data_length != length) return DfcTransactionMacInvalid;
        break;
    default:
        return DfcTransactionMacInvalid;
    }
    return dfc_transaction_mac_input_add_data(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               offset,
               length,
               data,
               data_length) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_data(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!uint24_is_valid(offset) || !uint24_is_valid(length)) return false;
    uint8_t header[8] = {command, file_number};
    write_uint24_le(header + 2, offset);
    write_uint24_le(header + 5, length);
    return append_entry(
        input, input_capacity, input_length, header, sizeof(header), data, data_length);
}

DfcTransactionMacStatus dfc_transaction_mac_add_record_update(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!verifier_is_valid(verifier) ||
       (command != DFC_CMD_UPDATE_RECORD && command != DFC_CMD_UPDATE_RECORD_ISO) ||
       !uint24_is_valid(record_number) || !uint24_is_valid(offset) || !uint24_is_valid(length) ||
       data_length != length || (data_length && !data))
        return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_record_update(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               record_number,
               offset,
               length,
               data,
               data_length) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_record_update(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length) {
    if(!uint24_is_valid(record_number) || !uint24_is_valid(offset) || !uint24_is_valid(length))
        return false;
    uint8_t header[11] = {command, file_number};
    write_uint24_le(header + 2, record_number);
    write_uint24_le(header + 5, offset);
    write_uint24_le(header + 8, length);
    return append_entry(
        input, input_capacity, input_length, header, sizeof(header), data, data_length);
}

bool dfc_transaction_mac_input_add_value(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    const uint8_t value[4]) {
    uint8_t header[6] = {command, file_number};
    if(!value) return false;
    memcpy(header + 2, value, 4);
    return append_entry(input, input_capacity, input_length, header, sizeof(header), NULL, 0);
}

DfcTransactionMacStatus dfc_transaction_mac_add_value(
    DfcTransactionMacVerifier* verifier,
    uint8_t command,
    uint8_t file_number,
    uint32_t value) {
    if(!verifier_is_valid(verifier) ||
       (command != DFC_CMD_GET_VALUE && command != DFC_CMD_CREDIT && command != DFC_CMD_DEBIT &&
        command != DFC_CMD_LIMITED_CREDIT))
        return DfcTransactionMacInvalid;
    uint8_t encoded[4];
    write_uint32_le(encoded, value);
    return dfc_transaction_mac_input_add_value(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               command,
               file_number,
               encoded) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

DfcTransactionMacStatus
    dfc_transaction_mac_add_clear_record(DfcTransactionMacVerifier* verifier, uint8_t file_number) {
    if(!verifier_is_valid(verifier)) return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_clear_record(
               verifier->input, verifier->input_capacity, &verifier->input_length, file_number) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

bool dfc_transaction_mac_input_add_clear_record(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t file_number) {
    const uint8_t header[] = {DFC_CMD_CLEAR_RECORD_FILE, file_number};
    return append_entry(input, input_capacity, input_length, header, sizeof(header), NULL, 0);
}

bool dfc_transaction_mac_input_add_reader_id(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    const uint8_t current_reader_id[16],
    const uint8_t encrypted_previous_reader_id[16]) {
    if(!current_reader_id) return false;
    uint8_t header[1 + DFC_TRANSACTION_READER_ID_LENGTH] = {DFC_CMD_COMMIT_READER_ID};
    memcpy(header + 1, current_reader_id, DFC_TRANSACTION_READER_ID_LENGTH);
    return append_entry(
        input,
        input_capacity,
        input_length,
        header,
        sizeof(header),
        encrypted_previous_reader_id,
        encrypted_previous_reader_id ? DFC_TRANSACTION_READER_ID_LENGTH : 0);
}

DfcTransactionMacStatus dfc_transaction_mac_add_reader_id(
    DfcTransactionMacVerifier* verifier,
    const uint8_t current_reader_id[DFC_TRANSACTION_READER_ID_LENGTH],
    const uint8_t encrypted_previous_reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    if(!verifier_is_valid(verifier) || !current_reader_id) return DfcTransactionMacInvalid;
    return dfc_transaction_mac_input_add_reader_id(
               verifier->input,
               verifier->input_capacity,
               &verifier->input_length,
               current_reader_id,
               encrypted_previous_reader_id) ?
               DfcTransactionMacOk :
               DfcTransactionMacCapacity;
}

DfcTransactionMacStatus dfc_transaction_mac_verify(
    const DfcTransactionMacVerifier* verifier,
    const uint8_t mac[DFC_WIRE_MAC_LENGTH],
    bool* verified) {
    if(verified) *verified = false;
    if(!verifier_is_valid(verifier) || verifier->input_length == 0 || !mac || !verified)
        return DfcTransactionMacInvalid;
    uint8_t vector[DFC_AES_KEY_LENGTH] = {
        DFC_TRANSACTION_MAC_DERIVATION_LABEL,
        DFC_DERIVATION_COUNTER_HIGH,
        DFC_DERIVATION_COUNTER_LOW,
        DFC_DERIVED_AES_KEY_LENGTH_HIGH,
        DFC_DERIVED_AES_KEY_LENGTH_LOW};
    write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, verifier->counter);
    memcpy(vector + DFC_TRANSACTION_VECTOR_UID_OFFSET, verifier->uid, verifier->uid_length);
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t wire_mac[DFC_WIRE_MAC_LENGTH] = {0};
    bool ok =
        aes_cmac(
            (uint8_t*)verifier->key, sizeof(verifier->key), vector, sizeof(vector), session_key) &&
        aes_cmac(
            session_key, sizeof(session_key), verifier->input, verifier->input_length, full_mac);
    if(ok) {
        dfc_truncate_aes_wire_mac(full_mac, wire_mac);
        *verified = dfc_ct_equal(wire_mac, mac, sizeof(wire_mac));
    }
    dfc_secure_wipe(vector, sizeof(vector));
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    dfc_secure_wipe(wire_mac, sizeof(wire_mac));
    return ok ? DfcTransactionMacOk : DfcTransactionMacCryptoFailed;
}
