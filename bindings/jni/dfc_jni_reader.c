#include "dfc_jni_internal.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_common.h"
#include "dfc_jni_layout.h"

JNIEXPORT jlong JNICALL Java_com_cindersocket_dfc_DfcNative_readerCreate(JNIEnv* env, jclass type) {
    (void)type;
    JniReader* wrapper = calloc(1, sizeof(*wrapper));
    if(wrapper == NULL) {
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return 0;
    }
    int32_t status = dfc_ffi_reader_session_new(&wrapper->session);
    if(status == DFC_FFI_OK) status = dfc_ffi_reader_exchange_new(&wrapper->exchange);
    if(status != DFC_FFI_OK) {
        dfc_ffi_reader_exchange_free(wrapper->exchange);
        dfc_ffi_reader_session_free(wrapper->session);
        secure_free(wrapper, sizeof(*wrapper));
        throw_dfc(env, status, 0, 0, "could not create reader");
        return 0;
    }
    return (jlong)(uintptr_t)wrapper;
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_readerFree(JNIEnv* env, jclass type, jlong handle) {
    (void)env;
    (void)type;
    JniReader* wrapper = (JniReader*)(uintptr_t)handle;
    if(wrapper == NULL) return;
    reader_clear_pending(wrapper);
    dfc_ffi_reader_exchange_free(wrapper->exchange);
    dfc_ffi_reader_session_free(wrapper->session);
    secure_free(wrapper, sizeof(*wrapper));
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_readerClear(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper != NULL) {
        dfc_ffi_reader_session_clear(wrapper->session);
        reader_clear_pending(wrapper);
    }
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_readerBegin(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint framing,
    jint instruction,
    jbyteArray data,
    jint communication,
    jint header_length) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return;
    uint8_t ins = 0, comm_mode = 0;
    uint32_t framing_id = 0;
    if(!jint_to_u32(env, framing, "framing out of range", &framing_id)) return;
    if(!jint_to_u8(env, instruction, "instruction out of range", &ins)) return;
    if(!jint_to_u8(env, communication, "communication mode out of range", &comm_mode)) return;
    size_t length = 0;
    uint8_t* bytes = copy_array(env, data, &length, false);
    if((*env)->ExceptionCheck(env)) return;
    reader_clear_pending(wrapper);
    wrapper->pending_data = bytes;
    wrapper->pending_data_len = length;
    int32_t status = dfc_ffi_reader_exchange_begin(
        wrapper->exchange,
        wrapper->session,
        framing_id,
        ins,
        wrapper->pending_data,
        length,
        comm_mode,
        (int32_t)header_length);
    if(status != DFC_FFI_OK) {
        reader_clear_pending(wrapper);
        throw_dfc(env, status, 0, 0, "could not begin reader exchange");
    }
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_readerAuthenticate(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint framing,
    jint cipher,
    jint key_number,
    jbyteArray key,
    jbyteArray random_a) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return;
    uint8_t cipher_id = 0, key_no = 0;
    uint32_t framing_id = 0;
    if(!jint_to_u32(env, framing, "framing out of range", &framing_id)) return;
    if(!jint_to_u8(env, cipher, "cipher out of range", &cipher_id)) return;
    if(!jint_to_u8(env, key_number, "key number out of range", &key_no)) return;
    uint8_t key_bytes[DFC_MAX_KEY_LEN];
    uint8_t random_bytes[DFC_ISO7816_AUTH_CHALLENGE_LONG];
    size_t key_len = 0, random_len = 0;
    if(!copy_bounded_array(
           env, key, key_bytes, sizeof(key_bytes), &key_len, "authentication key is too large") ||
       !copy_bounded_array(
           env,
           random_a,
           random_bytes,
           sizeof(random_bytes),
           &random_len,
           "authentication challenge is too large"))
        goto cleanup;
    int32_t status = dfc_ffi_reader_authenticate_begin(
        wrapper->exchange,
        wrapper->session,
        framing_id,
        cipher_id,
        key_no,
        key_bytes,
        key_len,
        random_bytes,
        random_len);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "could not begin authentication");
cleanup:
    dfc_ffi_secure_zero(key_bytes, sizeof(key_bytes));
    dfc_ffi_secure_zero(random_bytes, sizeof(random_bytes));
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_readerAuthenticateIso7816(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint key_reference,
    jint algorithm,
    jbyteArray key,
    jbyteArray random_first,
    jbyteArray random_second) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return;
    uint8_t key_ref = 0, algorithm_id = 0;
    if(!jint_to_u8(env, key_reference, "key reference out of range", &key_ref)) return;
    if(!jint_to_u8(env, algorithm, "algorithm out of range", &algorithm_id)) return;
    uint8_t key_bytes[DFC_MAX_KEY_LEN];
    uint8_t first_bytes[DFC_ISO7816_AUTH_CHALLENGE_LONG];
    uint8_t second_bytes[DFC_ISO7816_AUTH_CHALLENGE_LONG];
    size_t key_len = 0, first_len = 0, second_len = 0;
    if(!copy_bounded_array(
           env, key, key_bytes, sizeof(key_bytes), &key_len, "authentication key is too large") ||
       !copy_bounded_array(
           env,
           random_first,
           first_bytes,
           sizeof(first_bytes),
           &first_len,
           "authentication challenge is too large") ||
       !copy_bounded_array(
           env,
           random_second,
           second_bytes,
           sizeof(second_bytes),
           &second_len,
           "authentication challenge is too large"))
        goto cleanup;
    if(first_len != second_len) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "ISO 7816 challenge lengths differ");
        goto cleanup;
    }
    int32_t status = dfc_ffi_reader_authenticate_iso7816_begin(
        wrapper->exchange,
        wrapper->session,
        key_ref,
        key_bytes,
        key_len,
        algorithm_id,
        first_bytes,
        second_bytes,
        first_len);
    if(status != DFC_FFI_OK)
        throw_dfc(env, status, 0, 0, "could not begin ISO 7816 authentication");
cleanup:
    dfc_ffi_secure_zero(key_bytes, sizeof(key_bytes));
    dfc_ffi_secure_zero(first_bytes, sizeof(first_bytes));
    dfc_ffi_secure_zero(second_bytes, sizeof(second_bytes));
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_readerAuthenticateEv2(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint framing,
    jboolean first,
    jint key_number,
    jbyteArray key,
    jbyteArray random_a,
    jbyteArray capabilities) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return;
    uint8_t key_no = 0;
    uint32_t framing_id = 0;
    if(!jint_to_u32(env, framing, "framing out of range", &framing_id)) return;
    if(!jint_to_u8(env, key_number, "key number out of range", &key_no)) return;
    uint8_t key_bytes[DFC_AES_KEY_LENGTH];
    uint8_t random_bytes[DFC_EV2_RANDOM_LENGTH];
    uint8_t capability_bytes[DFC_EV2_CAPABILITY_LENGTH];
    size_t key_len = 0, random_len = 0, capabilities_len = 0;
    if(!copy_bounded_array(
           env, key, key_bytes, sizeof(key_bytes), &key_len, "EV2 key is too large") ||
       !copy_bounded_array(
           env,
           random_a,
           random_bytes,
           sizeof(random_bytes),
           &random_len,
           "EV2 challenge is too large") ||
       !copy_bounded_array(
           env,
           capabilities,
           capability_bytes,
           sizeof(capability_bytes),
           &capabilities_len,
           "EV2 capabilities are too large"))
        goto cleanup;
    if(key_len != 16 || random_len != 16) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "EV2 keys and challenges must be 16 bytes");
        goto cleanup;
    }
    int32_t status = dfc_ffi_reader_authenticate_ev2_begin(
        wrapper->exchange,
        wrapper->session,
        framing_id,
        first ? 1 : 0,
        key_no,
        key_bytes,
        random_bytes,
        capabilities_len == 0 ? NULL : capability_bytes,
        capabilities_len);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "could not begin EV2 authentication");
cleanup:
    dfc_ffi_secure_zero(key_bytes, sizeof(key_bytes));
    dfc_ffi_secure_zero(random_bytes, sizeof(random_bytes));
    dfc_ffi_secure_zero(capability_bytes, sizeof(capability_bytes));
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_readerStep(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray answer) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return NULL;
    uint8_t answer_bytes[JNI_READER_FRAME_MAX];
    size_t answer_len = 0;
    if(!copy_bounded_array_or_null(
           env,
           answer,
           answer_bytes,
           sizeof(answer_bytes),
           &answer_len,
           true,
           "reader answer is too large")) {
        dfc_ffi_secure_zero(answer_bytes, sizeof(answer_bytes));
        return NULL;
    }
    uint8_t frame[JNI_READER_FRAME_MAX];
    size_t frame_len = 0;
    int32_t status = dfc_ffi_reader_step(
        wrapper->exchange, answer_bytes, answer_len, frame, sizeof(frame), &frame_len);
    dfc_ffi_secure_zero(answer_bytes, sizeof(answer_bytes));
    if(status == 1) return make_array_and_wipe(env, frame, frame_len, sizeof(frame));
    dfc_ffi_secure_zero(frame, sizeof(frame));
    if(status == 0) {
        reader_clear_pending(wrapper);
        return NULL;
    }
    reader_clear_pending(wrapper);
    throw_dfc(
        env, status, 0, dfc_ffi_reader_result_status(wrapper->exchange), "reader exchange failed");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_readerResult(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return NULL;
    size_t length = 0;
    int32_t status = dfc_ffi_reader_result_data(wrapper->exchange, NULL, 0, &length);
    if(status != DFC_FFI_OK && status != DFC_FFI_BUFFER_TOO_SMALL) {
        throw_dfc(
            env,
            status,
            0,
            dfc_ffi_reader_result_status(wrapper->exchange),
            "could not read reader result");
        return NULL;
    }
    size_t capacity = length;
    uint8_t* result = capacity == 0 ? NULL : malloc(capacity);
    if(capacity != 0 && result == NULL) {
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return NULL;
    }
    status = dfc_ffi_reader_result_data(wrapper->exchange, result, capacity, &length);
    if(status != DFC_FFI_OK) {
        secure_free(result, capacity);
        throw_dfc(env, status, 0, 0, "could not read reader result");
        return NULL;
    }
    jbyteArray output = make_array(env, result, length);
    secure_free(result, capacity);
    return output;
}

JNIEXPORT jint JNICALL
    Java_com_cindersocket_dfc_DfcNative_readerStatus(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    return wrapper == NULL ? 0 : (jint)dfc_ffi_reader_result_status(wrapper->exchange);
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_readerState(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return NULL;
    DfcFfiReaderState state = {0};
    int32_t status = dfc_ffi_reader_session_state(wrapper->session, &state);
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(&state, sizeof(state));
        throw_dfc(env, status, 0, 0, "could not read reader state");
        return NULL;
    }
    uint8_t packed[DFC_JNI_READER_STATE_SIZE] = {0};
    packed[DFC_JNI_READER_STATE_AUTH_MODE_OFFSET] = state.auth_mode;
    packed[DFC_JNI_READER_STATE_KEY_OFFSET] = state.key_no;
    put_u32_be(packed + DFC_JNI_READER_STATE_COMMAND_COUNTER_OFFSET, state.ev2_command_counter);
    memcpy(
        packed + DFC_JNI_READER_STATE_TRANSACTION_ID_OFFSET,
        state.ev2_transaction_identifier,
        sizeof(state.ev2_transaction_identifier));
    memcpy(
        packed + DFC_JNI_READER_STATE_CARD_CAPABILITIES_OFFSET,
        state.ev2_card_capabilities,
        sizeof(state.ev2_card_capabilities));
    memcpy(
        packed + DFC_JNI_READER_STATE_READER_CAPABILITIES_OFFSET,
        state.ev2_reader_capabilities,
        sizeof(state.ev2_reader_capabilities));
    jbyteArray result = make_array_and_wipe(env, packed, sizeof(packed), sizeof(packed));
    dfc_ffi_secure_zero(&state, sizeof(state));
    return result;
}
