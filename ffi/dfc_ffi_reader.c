#include "dfc_ffi_internal.h"

#include <stdlib.h>
#include <string.h>

#if DFC_ENABLE_READER
#include "dfc_reader.h"

_Static_assert(
    DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH == DFC_READER_MAX_CLEAR_HEADER_LENGTH,
    "FFI reader header bound drifted");
#define ASSERT_READER_STATUS(ffi_status, core_status) \
    _Static_assert((ffi_status) == (core_status), "FFI reader status value drifted")
ASSERT_READER_STATUS(DFC_FFI_READER_OK, DfcReaderOk);
ASSERT_READER_STATUS(DFC_FFI_READER_PENDING, DfcReaderPending);
ASSERT_READER_STATUS(DFC_FFI_READER_INVALID, DfcReaderInvalid);
ASSERT_READER_STATUS(DFC_FFI_READER_BUFFER_TOO_SMALL, DfcReaderBufferTooSmall);
ASSERT_READER_STATUS(DFC_FFI_READER_PROTOCOL_ERROR, DfcReaderProtocolError);
ASSERT_READER_STATUS(DFC_FFI_READER_INTEGRITY_ERROR, DfcReaderIntegrityError);
ASSERT_READER_STATUS(DFC_FFI_READER_CARD_ERROR, DfcReaderCardError);
ASSERT_READER_STATUS(DFC_FFI_READER_UNSUPPORTED, DfcReaderUnsupported);
#undef ASSERT_READER_STATUS
_Static_assert(
    DFC_FFI_READER_FRAMING_ISO7816 == DfcReaderFramingIso7816 &&
        DFC_FFI_READER_FRAMING_NATIVE == DfcReaderFramingNative,
    "FFI reader framing value drifted");
_Static_assert(
    DFC_FFI_COMM_PLAIN == DFC_COMM_PLAIN && DFC_FFI_COMM_MAC == DFC_COMM_MAC &&
        DFC_FFI_COMM_ENCIPHERED == DFC_COMM_ENCIPHERED,
    "FFI communication mode drifted");
_Static_assert(
    DFC_FFI_AUTH_LEGACY == DFC_CMD_AUTHENTICATE_LEGACY &&
        DFC_FFI_AUTH_ISO == DFC_CMD_AUTHENTICATE_ISO &&
        DFC_FFI_AUTH_AES == DFC_CMD_AUTHENTICATE_AES &&
        DFC_FFI_AUTH_EV2 == DFC_CMD_AUTHENTICATE_EV2_FIRST,
    "FFI authentication command drifted");
_Static_assert(
    DFC_FFI_ISO_AUTH_TDEA2 == DFC_ISO7816_AUTH_ALGORITHM_2TDEA &&
        DFC_FFI_ISO_AUTH_TDEA3 == DFC_ISO7816_AUTH_ALGORITHM_3TDEA &&
        DFC_FFI_ISO_AUTH_AES == DFC_ISO7816_AUTH_ALGORITHM_AES,
    "FFI ISO authentication algorithm drifted");

struct DfcFfiReaderSession {
    DfcReaderSession session;
};

struct DfcFfiReaderExchange {
    DfcReaderExchange exchange;
};
#endif

#if DFC_ENABLE_READER
int32_t dfc_ffi_reader_session_new(DfcFfiReaderSession** out) {
    if(!out) return DFC_FFI_INVALID_ARGUMENT;
    *out = calloc(1, sizeof(**out));
    if(!*out) return DFC_FFI_OUT_OF_MEMORY;
    dfc_reader_session_init(&(*out)->session);
    return DfcReaderOk;
}

void dfc_ffi_reader_session_free(DfcFfiReaderSession* session) {
    if(!session) return;
    dfc_secure_wipe(session, sizeof(*session));
    free(session);
}

void dfc_ffi_reader_session_clear(DfcFfiReaderSession* session) {
    if(session) dfc_reader_session_clear(&session->session);
}

int32_t dfc_ffi_reader_session_state(const DfcFfiReaderSession* session, DfcFfiReaderState* out) {
    if(!session || !out) return DFC_FFI_INVALID_ARGUMENT;
    const DfcReaderSession* s = &session->session;
    memset(out, 0, sizeof(*out));
    out->auth_mode = s->auth_mode;
    out->key_no = s->key_no;
    out->ev2_command_counter = s->ev2_command_counter;
    memcpy(out->ev2_transaction_identifier, s->ev2_transaction_identifier, 4);
    memcpy(out->ev2_card_capabilities, s->ev2_card_capabilities, 6);
    memcpy(out->ev2_reader_capabilities, s->ev2_reader_capabilities, 6);
    return DfcReaderOk;
}

int32_t dfc_ffi_reader_exchange_new(DfcFfiReaderExchange** out) {
    if(!out) return DFC_FFI_INVALID_ARGUMENT;
    *out = calloc(1, sizeof(**out));
    return *out ? DfcReaderOk : DFC_FFI_OUT_OF_MEMORY;
}

void dfc_ffi_reader_exchange_free(DfcFfiReaderExchange* exchange) {
    if(!exchange) return;
    dfc_secure_wipe(exchange, sizeof(*exchange));
    free(exchange);
}

int32_t dfc_ffi_reader_authenticate_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t cipher,
    uint8_t key_no,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* random_a,
    size_t random_a_len) {
    if(!exchange || !session || framing > DfcReaderFramingNative) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_authenticate_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        cipher,
        key_no,
        key,
        key_len,
        random_a,
        random_a_len);
}

int32_t dfc_ffi_reader_authenticate_iso7816_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint8_t key_reference,
    const uint8_t* key,
    size_t key_len,
    uint8_t algorithm,
    const uint8_t* random_first,
    const uint8_t* random_second,
    size_t random_len) {
    if(!exchange || !session) return DFC_FFI_INVALID_ARGUMENT;
#if DFC_ENABLE_ISO7816_AUTH
    return dfc_reader_authenticate_iso7816_begin(
        &exchange->exchange,
        &session->session,
        key_reference,
        key,
        key_len,
        algorithm,
        random_first,
        random_second,
        random_len);
#else
    (void)key_reference;
    (void)key;
    (void)key_len;
    (void)algorithm;
    (void)random_first;
    (void)random_second;
    (void)random_len;
    return DfcReaderUnsupported;
#endif
}

int32_t dfc_ffi_reader_authenticate_ev2_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t first,
    uint8_t key_no,
    const uint8_t* key,
    const uint8_t* random_a,
    const uint8_t* capabilities,
    size_t capabilities_len) {
    if(!exchange || !session || framing > DfcReaderFramingNative) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_authenticate_ev2_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        first != 0,
        key_no,
        key,
        random_a,
        capabilities,
        capabilities_len);
}

int32_t dfc_ffi_reader_exchange_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t ins,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode,
    int32_t header_len) {
    // -1 asks the reader to derive the head; any other value is a head length and
    // must fit the reader's bound before it is narrowed to the option's octet.
    if(!exchange || !session || framing > DfcReaderFramingNative || header_len < -1 ||
       header_len > DFC_READER_MAX_CLEAR_HEADER_LENGTH) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    DfcCommand command = {0};
    DfcReaderStatus status = DfcReaderInvalid;
    if(dfc_command_encode_raw(&command, ins, data, data_len) != DfcCommandOk) goto cleanup;
    DfcReaderOptions options = {0};
    options.comm_mode = comm_mode;
    if(header_len >= 0) {
        options.has_header_len = true;
        options.header_len = (uint8_t)header_len;
    }
    status = dfc_reader_exchange_begin(
        &exchange->exchange, &session->session, (DfcReaderFraming)framing, &command, &options);
cleanup:
    // The reader owns its prepared frame; the FFI stack copy must not retain command data.
    dfc_secure_wipe(&command, sizeof(command));
    return status;
}

int32_t dfc_ffi_reader_write_data_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    if(!exchange || !session || framing > DfcReaderFramingNative) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_write_data_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        file_number,
        offset,
        data,
        data_len,
        comm_mode);
}

int32_t dfc_ffi_reader_write_record_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    if(!exchange || !session || framing > DfcReaderFramingNative) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_write_record_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        file_number,
        offset,
        data,
        data_len,
        comm_mode);
}

int32_t dfc_ffi_reader_update_record_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    if(!exchange || !session || framing > DfcReaderFramingNative) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_update_record_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        file_number,
        record_number,
        offset,
        data,
        data_len,
        comm_mode);
}

int32_t dfc_ffi_reader_create_delegated_application_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    const uint8_t* header,
    size_t header_len,
    const uint8_t* dam_encryption_key,
    const uint8_t* dam_mac_key,
    const uint8_t* random_prefix,
    const uint8_t* initial_key,
    size_t initial_key_len,
    uint8_t initial_version) {
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(!exchange || !session || !header || header_len != DFC_DELEGATED_CREATE_HEADER_LENGTH - 1 ||
       framing > DfcReaderFramingNative) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    DfcCommandCreateDelegatedApplication app;
    memcpy(app.aid, header, 3);
    app.slot_number = (uint16_t)(header[3] | (header[4] << 8));
    app.slot_version = header[5];
    app.quota_limit = (uint16_t)(header[6] | (header[7] << 8));
    app.key_settings_1 = header[8];
    app.key_settings_2 = header[9];
    return dfc_reader_create_delegated_application_begin(
        &exchange->exchange,
        &session->session,
        (DfcReaderFraming)framing,
        &app,
        dam_encryption_key,
        dam_mac_key,
        random_prefix,
        initial_key,
        initial_key_len,
        initial_version);
#else
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(header);
    DFC_UNUSED(header_len);
    DFC_UNUSED(dam_encryption_key);
    DFC_UNUSED(dam_mac_key);
    DFC_UNUSED(random_prefix);
    DFC_UNUSED(initial_key);
    DFC_UNUSED(initial_key_len);
    DFC_UNUSED(initial_version);
    return DFC_FFI_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_reader_step(
    DfcFfiReaderExchange* exchange,
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
    if(!exchange) return DFC_FFI_INVALID_ARGUMENT;
    DfcReaderStatus status =
        dfc_reader_step(&exchange->exchange, response, response_len, out, out_cap, out_len);
    if(status != DfcReaderOk && status != DfcReaderPending && status != DfcReaderBufferTooSmall) {
        dfc_secure_wipe(exchange->exchange.data, sizeof(exchange->exchange.data));
        exchange->exchange.data_len = 0;
    }
    return status;
}

uint8_t dfc_ffi_reader_result_status(const DfcFfiReaderExchange* exchange) {
    return exchange ? dfc_reader_result_status(&exchange->exchange) : 0;
}

int32_t dfc_ffi_reader_result_data(
    DfcFfiReaderExchange* exchange,
    uint8_t* out,
    size_t cap,
    size_t* len) {
    if(!exchange || !len || (!out && cap)) return DFC_FFI_INVALID_ARGUMENT;
    size_t data_len = 0;
    const uint8_t* data = dfc_reader_result_data(&exchange->exchange, &data_len);
    *len = data_len;
    if(!out) return DfcReaderOk;
    if(data_len > cap) return DFC_FFI_BUFFER_TOO_SMALL;
    if(data_len) memcpy(out, data, data_len);
    // A successful copy transfers the response to caller-owned storage.
    dfc_secure_wipe(exchange->exchange.data, sizeof(exchange->exchange.data));
    exchange->exchange.data_len = 0;
    return DfcReaderOk;
}

int32_t dfc_ffi_reader_change_key_cryptogram(
    const DfcFfiReaderSession* session,
    uint8_t key_no,
    const uint8_t* new_key,
    size_t key_len,
    const uint8_t* current_key,
    uint8_t aes_key,
    uint8_t new_version,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
    if(!session) return DFC_FFI_INVALID_ARGUMENT;
    return dfc_reader_change_key_cryptogram(
        &session->session,
        key_no,
        new_key,
        key_len,
        current_key,
        aes_key != 0,
        new_version,
        out,
        out_cap,
        out_len);
}

int32_t dfc_ffi_reader_change_key_ev2_data(
    const DfcFfiReaderSession* session,
    uint8_t key_set_no,
    uint8_t key_no,
    const uint8_t* new_key,
    const uint8_t* current_key,
    uint8_t new_version,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(!session || !out || !out_len) return DFC_FFI_INVALID_ARGUMENT;
    DfcCommand command = {0};
    DfcReaderStatus st = dfc_reader_change_key_ev2_command(
        &session->session, key_set_no, key_no, new_key, current_key, new_version, &command);
    if(st == DfcReaderOk && command.data_len > out_cap) {
        st = DFC_FFI_BUFFER_TOO_SMALL;
    } else if(st == DfcReaderOk) {
        memcpy(out, command.data, command.data_len);
        *out_len = command.data_len;
    }
    dfc_secure_wipe(&command, sizeof(command));
    return st;
#else
    DFC_UNUSED(session);
    DFC_UNUSED(key_set_no);
    DFC_UNUSED(key_no);
    DFC_UNUSED(new_key);
    DFC_UNUSED(current_key);
    DFC_UNUSED(new_version);
    DFC_UNUSED(out);
    DFC_UNUSED(out_cap);
    DFC_UNUSED(out_len);
    return DFC_FFI_UNSUPPORTED;
#endif
}
#else
int32_t dfc_ffi_reader_session_new(DfcFfiReaderSession** out) {
    if(out) *out = NULL;
    return DFC_FFI_UNSUPPORTED;
}

void dfc_ffi_reader_session_free(DfcFfiReaderSession* session) {
    DFC_UNUSED(session);
}

void dfc_ffi_reader_session_clear(DfcFfiReaderSession* session) {
    DFC_UNUSED(session);
}

int32_t dfc_ffi_reader_session_state(const DfcFfiReaderSession* session, DfcFfiReaderState* out) {
    DFC_UNUSED(session);
    if(out) memset(out, 0, sizeof(*out));
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_exchange_new(DfcFfiReaderExchange** out) {
    if(out) *out = NULL;
    return DFC_FFI_UNSUPPORTED;
}

void dfc_ffi_reader_exchange_free(DfcFfiReaderExchange* exchange) {
    DFC_UNUSED(exchange);
}

int32_t dfc_ffi_reader_authenticate_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t cipher,
    uint8_t key_no,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* random_a,
    size_t random_a_len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(cipher);
    DFC_UNUSED(key_no);
    DFC_UNUSED(key);
    DFC_UNUSED(key_len);
    DFC_UNUSED(random_a);
    DFC_UNUSED(random_a_len);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_authenticate_iso7816_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint8_t key_reference,
    const uint8_t* key,
    size_t key_len,
    uint8_t algorithm,
    const uint8_t* random_first,
    const uint8_t* random_second,
    size_t random_len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(key_reference);
    DFC_UNUSED(key);
    DFC_UNUSED(key_len);
    DFC_UNUSED(algorithm);
    DFC_UNUSED(random_first);
    DFC_UNUSED(random_second);
    DFC_UNUSED(random_len);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_authenticate_ev2_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t first,
    uint8_t key_no,
    const uint8_t* key,
    const uint8_t* random_a,
    const uint8_t* capabilities,
    size_t capabilities_len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(first);
    DFC_UNUSED(key_no);
    DFC_UNUSED(key);
    DFC_UNUSED(random_a);
    DFC_UNUSED(capabilities);
    DFC_UNUSED(capabilities_len);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_exchange_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t ins,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode,
    int32_t header_len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(ins);
    DFC_UNUSED(data);
    DFC_UNUSED(data_len);
    DFC_UNUSED(comm_mode);
    DFC_UNUSED(header_len);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_write_data_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(file_number);
    DFC_UNUSED(offset);
    DFC_UNUSED(data);
    DFC_UNUSED(data_len);
    DFC_UNUSED(comm_mode);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_write_record_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(file_number);
    DFC_UNUSED(offset);
    DFC_UNUSED(data);
    DFC_UNUSED(data_len);
    DFC_UNUSED(comm_mode);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_update_record_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    const uint8_t* data,
    size_t data_len,
    uint8_t comm_mode) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(file_number);
    DFC_UNUSED(record_number);
    DFC_UNUSED(offset);
    DFC_UNUSED(data);
    DFC_UNUSED(data_len);
    DFC_UNUSED(comm_mode);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_create_delegated_application_begin(
    DfcFfiReaderExchange* exchange,
    DfcFfiReaderSession* session,
    uint32_t framing,
    const uint8_t* header,
    size_t header_len,
    const uint8_t* dam_encryption_key,
    const uint8_t* dam_mac_key,
    const uint8_t* random_prefix,
    const uint8_t* initial_key,
    size_t initial_key_len,
    uint8_t initial_version) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(session);
    DFC_UNUSED(framing);
    DFC_UNUSED(header);
    DFC_UNUSED(header_len);
    DFC_UNUSED(dam_encryption_key);
    DFC_UNUSED(dam_mac_key);
    DFC_UNUSED(random_prefix);
    DFC_UNUSED(initial_key);
    DFC_UNUSED(initial_key_len);
    DFC_UNUSED(initial_version);
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_step(
    DfcFfiReaderExchange* exchange,
    const uint8_t* response,
    size_t response_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(response);
    DFC_UNUSED(response_len);
    DFC_UNUSED(out);
    DFC_UNUSED(out_cap);
    if(out_len) *out_len = 0;
    return DFC_FFI_UNSUPPORTED;
}

uint8_t dfc_ffi_reader_result_status(const DfcFfiReaderExchange* exchange) {
    DFC_UNUSED(exchange);
    return 0;
}

int32_t dfc_ffi_reader_result_data(
    DfcFfiReaderExchange* exchange,
    uint8_t* out,
    size_t cap,
    size_t* len) {
    DFC_UNUSED(exchange);
    DFC_UNUSED(out);
    DFC_UNUSED(cap);
    if(len) *len = 0;
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_change_key_cryptogram(
    const DfcFfiReaderSession* session,
    uint8_t key_no,
    const uint8_t* new_key,
    size_t key_len,
    const uint8_t* current_key,
    uint8_t aes_key,
    uint8_t new_version,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
    DFC_UNUSED(session);
    DFC_UNUSED(key_no);
    DFC_UNUSED(new_key);
    DFC_UNUSED(key_len);
    DFC_UNUSED(current_key);
    DFC_UNUSED(aes_key);
    DFC_UNUSED(new_version);
    DFC_UNUSED(out);
    DFC_UNUSED(out_cap);
    if(out_len) *out_len = 0;
    return DFC_FFI_UNSUPPORTED;
}

int32_t dfc_ffi_reader_change_key_ev2_data(
    const DfcFfiReaderSession* session,
    uint8_t key_set_no,
    uint8_t key_no,
    const uint8_t* new_key,
    const uint8_t* current_key,
    uint8_t new_version,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len) {
    DFC_UNUSED(session);
    DFC_UNUSED(key_set_no);
    DFC_UNUSED(key_no);
    DFC_UNUSED(new_key);
    DFC_UNUSED(current_key);
    DFC_UNUSED(new_version);
    DFC_UNUSED(out);
    DFC_UNUSED(out_cap);
    if(out_len) *out_len = 0;
    return DFC_FFI_UNSUPPORTED;
}
#endif
