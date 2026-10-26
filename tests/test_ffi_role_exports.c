#include "dfc_build_config.h"
#include "dfc_ffi.h"

#include <string.h>

int main(void) {
#if !DFC_ENABLE_EMULATOR
    DfcFfiActivation activation;
    DfcFfiSnapshot snapshot;
    DfcFfiDiagnosticSnapshot diagnostic;
    DfcFfiCredential* exported = (DfcFfiCredential*)1;
    size_t response_len = 1;
    memset(&activation, 0xA5, sizeof(activation));
    memset(&snapshot, 0xA5, sizeof(snapshot));
    memset(&diagnostic, 0xA5, sizeof(diagnostic));

    if(dfc_ffi_picc_activate(NULL, &activation) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_response_capacity() != 0 ||
       dfc_ffi_picc_exchange(NULL, NULL, 0, NULL, 0, &response_len) != DFC_FFI_UNSUPPORTED ||
       response_len != 0 ||
       dfc_ffi_picc_frame_exchange(NULL, NULL, 0, NULL, 0, &response_len) != DFC_FFI_UNSUPPORTED ||
       response_len != 0 || dfc_ffi_picc_field_off(NULL) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_reset_protocol(NULL) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_advance_time(NULL, 1) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_snapshot(NULL, &snapshot) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_diagnostic_snapshot(NULL, &diagnostic) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_picc_export(NULL, &exported) != DFC_FFI_UNSUPPORTED || exported != NULL ||
       dfc_ffi_picc_mark_persisted(NULL) != DFC_FFI_UNSUPPORTED)
        return 1;

    DfcFfiActivation empty_activation = {0};
    DfcFfiSnapshot empty_snapshot = {0};
    DfcFfiDiagnosticSnapshot empty_diagnostic = {0};
    if(memcmp(&activation, &empty_activation, sizeof(activation)) != 0 ||
       memcmp(&snapshot, &empty_snapshot, sizeof(snapshot)) != 0 ||
       memcmp(&diagnostic, &empty_diagnostic, sizeof(diagnostic)) != 0)
        return 1;
#endif

#if !DFC_ENABLE_READER
    DfcFfiReaderSession* session = (DfcFfiReaderSession*)1;
    DfcFfiReaderExchange* exchange = (DfcFfiReaderExchange*)1;
    DfcFfiReaderState state;
    size_t output_len = 1;
    memset(&state, 0xA5, sizeof(state));
    if(dfc_ffi_reader_session_new(&session) != DFC_FFI_UNSUPPORTED || session != NULL ||
       dfc_ffi_reader_exchange_new(&exchange) != DFC_FFI_UNSUPPORTED || exchange != NULL ||
       dfc_ffi_reader_session_state(NULL, &state) != DFC_FFI_UNSUPPORTED ||
       dfc_ffi_reader_step(NULL, NULL, 0, NULL, 0, &output_len) != DFC_FFI_UNSUPPORTED ||
       output_len != 0)
        return 1;
    DfcFfiReaderState empty_state = {0};
    if(memcmp(&state, &empty_state, sizeof(state)) != 0) return 1;
#endif
    return 0;
}
