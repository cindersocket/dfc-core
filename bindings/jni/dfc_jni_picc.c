#include "dfc_jni_internal.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_common.h"
#include "dfc_jni_layout.h"
#include "dfc_jni_queue.h"

JNIEXPORT jlong JNICALL Java_com_cindersocket_dfc_DfcNative_piccCreate(
    JNIEnv* env,
    jclass type,
    jbyteArray content,
    jbyteArray random_script) {
    (void)type;
    DfcFfiCredential* credential = NULL;
    if(!load_credential(env, content, &credential)) return 0;
    JniPicc* wrapper = calloc(1, sizeof(*wrapper));
    if(wrapper == NULL) {
        dfc_ffi_credential_free(credential);
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return 0;
    }
    if(random_script != NULL) {
        wrapper->replay_random = true;
        wrapper->random = copy_array(env, random_script, &wrapper->random_len, true);
        if((*env)->ExceptionCheck(env)) {
            secure_free(wrapper, sizeof(*wrapper));
            dfc_ffi_credential_free(credential);
            return 0;
        }
    }
    int32_t status = dfc_ffi_picc_create_take(
        &credential, random_script == NULL ? NULL : scripted_random, wrapper, &wrapper->picc);
    dfc_ffi_credential_free(credential);
    if(status != DFC_FFI_OK) {
        secure_free(wrapper->random, wrapper->random_len);
        secure_free(wrapper, sizeof(*wrapper));
        throw_dfc(env, status, 0, 0, "could not create virtual PICC");
        return 0;
    }
    return (jlong)(uintptr_t)wrapper;
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_piccAppendReplayRandom(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray bytes) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    if(!wrapper->replay_random) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "PICC does not use replay randomness");
        return;
    }
    if(bytes == NULL) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "null byte array");
        return;
    }
    if(wrapper->random_offset > wrapper->random_len) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid replay random queue");
        return;
    }
    size_t append_len = (size_t)(*env)->GetArrayLength(env, bytes);
    size_t remaining = wrapper->random_len - wrapper->random_offset;
    size_t total = 0;
    if(!dfc_jni_replay_queue_length(remaining, append_len, &total)) {
        throw_dfc(env, DFC_FFI_BUFFER_TOO_SMALL, 0, 0, "replay random queue is too large");
        return;
    }
    uint8_t* combined = total == 0 ? NULL : malloc(total);
    if(total != 0 && combined == NULL) {
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return;
    }
    if(remaining != 0) memcpy(combined, wrapper->random + wrapper->random_offset, remaining);
    if(append_len != 0) {
        (*env)->GetByteArrayRegion(
            env, bytes, 0, (jsize)append_len, (jbyte*)(combined + remaining));
        if((*env)->ExceptionCheck(env)) {
            secure_free(combined, total);
            return;
        }
    }
    clear_replay_random(wrapper);
    wrapper->random = combined;
    wrapper->random_len = total;
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_piccClearReplayRandom(
    JNIEnv* env,
    jclass type,
    jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    if(!wrapper->replay_random) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "PICC does not use replay randomness");
        return;
    }
    clear_replay_random(wrapper);
}

JNIEXPORT jint JNICALL Java_com_cindersocket_dfc_DfcNative_piccReplayRandomRemaining(
    JNIEnv* env,
    jclass type,
    jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return 0;
    if(!wrapper->replay_random) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "PICC does not use replay randomness");
        return 0;
    }
    if(wrapper->random_offset > wrapper->random_len ||
       wrapper->random_len - wrapper->random_offset > (size_t)INT_MAX) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid replay random queue");
        return 0;
    }
    return (jint)(wrapper->random_len - wrapper->random_offset);
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccFree(JNIEnv* env, jclass type, jlong handle) {
    (void)env;
    (void)type;
    JniPicc* wrapper = (JniPicc*)(uintptr_t)handle;
    if(wrapper == NULL) return;
    dfc_ffi_picc_free(wrapper->picc);
    clear_replay_random(wrapper);
    secure_free(wrapper, sizeof(*wrapper));
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccActivate(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return NULL;
    DfcFfiActivation activation = {0};
    int32_t status = dfc_ffi_picc_activate(wrapper->picc, &activation);
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(&activation, sizeof(activation));
        throw_dfc(env, status, 0, 0, "virtual PICC activation failed");
        return NULL;
    }
    uint8_t packed[DFC_JNI_ACTIVATION_MAX_SIZE];
    size_t offset = 0;
    packed[offset++] = (uint8_t)activation.uid_len;
    memcpy(packed + offset, activation.uid, activation.uid_len);
    offset += activation.uid_len;
    packed[offset++] = (uint8_t)activation.atqa_len;
    memcpy(packed + offset, activation.atqa, activation.atqa_len);
    offset += activation.atqa_len;
    packed[offset++] = activation.sak;
    packed[offset++] = (uint8_t)activation.ats_len;
    memcpy(packed + offset, activation.ats, activation.ats_len);
    offset += activation.ats_len;
    jbyteArray result = make_array_and_wipe(env, packed, offset, sizeof(packed));
    dfc_ffi_secure_zero(&activation, sizeof(activation));
    return result;
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccSnapshot(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return NULL;
    DfcFfiSnapshot snapshot = {0};
    int32_t status = dfc_ffi_picc_snapshot(wrapper->picc, &snapshot);
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(&snapshot, sizeof(snapshot));
        throw_dfc(env, status, 0, 0, "could not read virtual PICC state");
        return NULL;
    }
    uint8_t packed[DFC_JNI_SNAPSHOT_SIZE] = {0};
    packed[DFC_JNI_SNAPSHOT_SELECTED_OFFSET] = (uint8_t)snapshot.selected;
    put_u32_be(
        packed + DFC_JNI_SNAPSHOT_APPLICATION_INDEX_OFFSET, snapshot.selected_application_index);
    memcpy(packed + DFC_JNI_SNAPSHOT_AID_OFFSET, snapshot.selected_aid, 3);
    packed[DFC_JNI_SNAPSHOT_DIRTY_OFFSET] = snapshot.dirty;
    packed[DFC_JNI_SNAPSHOT_AUTH_MODE_OFFSET] = snapshot.auth_mode;
    packed[DFC_JNI_SNAPSHOT_AUTH_KEY_OFFSET] = snapshot.auth_key_no;
    put_u32_be(packed + DFC_JNI_SNAPSHOT_COMMAND_COUNTER_OFFSET, snapshot.ev2_command_counter);
    packed[DFC_JNI_SNAPSHOT_EV2_ACTIVE_OFFSET] = snapshot.ev2_active;
    packed[DFC_JNI_SNAPSHOT_VIRTUAL_CARD_OFFSET] = snapshot.virtual_card_selected;
    packed[DFC_JNI_SNAPSHOT_PROXIMITY_OFFSET] = snapshot.proximity_verified;
    jbyteArray result = make_array_and_wipe(env, packed, sizeof(packed), sizeof(packed));
    dfc_ffi_secure_zero(&snapshot, sizeof(snapshot));
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_piccDiagnosticSnapshot(
    JNIEnv* env,
    jclass type,
    jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return NULL;
    DfcFfiDiagnosticSnapshot snapshot = {0};
    int32_t status = dfc_ffi_picc_diagnostic_snapshot(wrapper->picc, &snapshot);
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(&snapshot, sizeof(snapshot));
        throw_dfc(env, status, 0, 0, "could not read diagnostic PICC state");
        return NULL;
    }
    uint8_t packed[DFC_JNI_DIAGNOSTIC_SIZE] = {0};
    memcpy(
        packed + DFC_JNI_DIAGNOSTIC_TRANSACTION_ID_OFFSET,
        snapshot.transaction_identifier,
        sizeof(snapshot.transaction_identifier));
    memcpy(
        packed + DFC_JNI_DIAGNOSTIC_ENCRYPTION_KEY_OFFSET,
        snapshot.encryption_key,
        sizeof(snapshot.encryption_key));
    memcpy(packed + DFC_JNI_DIAGNOSTIC_MAC_KEY_OFFSET, snapshot.mac_key, sizeof(snapshot.mac_key));
    jbyteArray result = make_array_and_wipe(env, packed, sizeof(packed), sizeof(packed));
    dfc_ffi_secure_zero(&snapshot, sizeof(snapshot));
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_piccExchange(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray input,
    jboolean frame) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return NULL;
    size_t input_len = 0;
    uint8_t* input_bytes = copy_array(env, input, &input_len, false);
    if((*env)->ExceptionCheck(env)) return NULL;
    uint8_t initial_response[JNI_PICC_RESPONSE_INITIAL];
    uint8_t* response = initial_response;
    size_t response_capacity = sizeof(initial_response);
    size_t response_len = 0;
    int32_t status = picc_exchange(
        wrapper, input_bytes, input_len, frame, response, response_capacity, &response_len);
    if(status == DFC_FFI_PICC_BUFFER_TOO_SMALL) {
        response_capacity = dfc_ffi_picc_response_capacity();
        if(response_capacity <= sizeof(initial_response) || response_capacity > INT_MAX) {
            secure_free(input_bytes, input_len);
            dfc_ffi_secure_zero(initial_response, sizeof(initial_response));
            throw_dfc(env, status, 0, 0, "invalid virtual PICC response capacity");
            return NULL;
        }
        response = malloc(response_capacity);
        if(response == NULL) {
            secure_free(input_bytes, input_len);
            dfc_ffi_secure_zero(initial_response, sizeof(initial_response));
            throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
            return NULL;
        }
        response_len = 0;
        status = picc_exchange(
            wrapper, input_bytes, input_len, frame, response, response_capacity, &response_len);
    }
    secure_free(input_bytes, input_len);
    if(status != DFC_FFI_OK) {
        if(response == initial_response) {
            dfc_ffi_secure_zero(initial_response, sizeof(initial_response));
        } else {
            secure_free(response, response_capacity);
        }
        throw_dfc(env, status, 0, 0, "virtual PICC exchange failed");
        return NULL;
    }
    if(response_len > response_capacity) {
        if(response == initial_response) {
            dfc_ffi_secure_zero(initial_response, sizeof(initial_response));
        } else {
            secure_free(response, response_capacity);
        }
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid virtual PICC response length");
        return NULL;
    }
    jbyteArray result = make_array(env, response, response_len);
    if(response == initial_response) {
        dfc_ffi_secure_zero(initial_response, sizeof(initial_response));
    } else {
        secure_free(response, response_capacity);
    }
    return result;
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccFieldOff(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    int32_t status = dfc_ffi_picc_field_off(wrapper->picc);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "virtual PICC field-off failed");
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccResetProtocol(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    int32_t status = dfc_ffi_picc_reset_protocol(wrapper->picc);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "virtual PICC reset failed");
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_piccAdvanceTime(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jlong milliseconds) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    uint32_t elapsed = 0;
    if(!jlong_to_u32(env, milliseconds, "milliseconds out of range", &elapsed)) return;
    int32_t status = dfc_ffi_picc_advance_time(wrapper->picc, elapsed);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "virtual PICC time advance failed");
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccMarkPersisted(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return;
    int32_t status = dfc_ffi_picc_mark_persisted(wrapper->picc);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "virtual PICC persistence reset failed");
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccExport(JNIEnv* env, jclass type, jlong handle) {
    (void)type;
    JniPicc* wrapper = picc_handle(env, handle);
    if(wrapper == NULL) return NULL;
    DfcFfiCredential* credential = NULL;
    int32_t status = dfc_ffi_picc_export(wrapper->picc, &credential);
    if(status != DFC_FFI_OK) {
        throw_dfc(env, status, 0, 0, "could not export virtual PICC");
        return NULL;
    }
    jbyteArray result = encode_credential(env, credential);
    dfc_ffi_credential_free(credential);
    return result;
}
