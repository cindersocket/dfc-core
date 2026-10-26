#include <jni.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dfc_common.h"
#include "dfc_ffi.h"
#include "dfc_ffi_layout.h"
#include "dfc_jni_layout.h"
#include "dfc_jni_internal.h"
#include "dfc_jni_queue.h"

void throw_dfc(
    JNIEnv* env,
    int32_t status,
    uint32_t line,
    uint8_t card_status,
    const char* message) {
    jclass type = (*env)->FindClass(env, "com/cindersocket/dfc/DfcException");
    if(type == NULL) return;
    jmethodID constructor = (*env)->GetMethodID(env, type, "<init>", "(Ljava/lang/String;III)V");
    if(constructor == NULL) return;
    jstring text = (*env)->NewStringUTF(
        env, message != NULL && message[0] != '\0' ? message : "dfc native failure");
    if(text == NULL) return;
    jobject error = (*env)->NewObject(
        env, type, constructor, text, (jint)status, (jint)line, (jint)card_status);
    if(error != NULL) (*env)->Throw(env, (jthrowable)error);
}

void secure_free(void* buffer, size_t length) {
    if(buffer == NULL) return;
    dfc_ffi_secure_zero(buffer, length);
    free(buffer);
}

void clear_replay_random(JniPicc* wrapper) {
    secure_free(wrapper->random, wrapper->random_len);
    wrapper->random = NULL;
    wrapper->random_len = 0;
    wrapper->random_offset = 0;
}

uint8_t* copy_array(JNIEnv* env, jbyteArray array, size_t* length, bool nullable) {
    if(array == NULL) {
        *length = 0;
        if(!nullable) throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "null byte array");
        return NULL;
    }
    jsize java_length = (*env)->GetArrayLength(env, array);
    *length = (size_t)java_length;
    if(java_length == 0) return NULL;
    uint8_t* bytes = malloc((size_t)java_length);
    if(bytes == NULL) {
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, array, 0, java_length, (jbyte*)bytes);
    if((*env)->ExceptionCheck(env)) {
        secure_free(bytes, (size_t)java_length);
        return NULL;
    }
    return bytes;
}

bool copy_bounded_array_or_null(
    JNIEnv* env,
    jbyteArray array,
    uint8_t* scratch,
    size_t capacity,
    size_t* length,
    bool nullable,
    const char* too_large_message) {
    *length = 0;
    if(array == NULL) {
        if(nullable) return true;
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "null byte array");
        return false;
    }
    jsize java_length = (*env)->GetArrayLength(env, array);
    if((*env)->ExceptionCheck(env)) return false;
    if((size_t)java_length > capacity) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, too_large_message);
        return false;
    }
    if(java_length != 0) {
        (*env)->GetByteArrayRegion(env, array, 0, java_length, (jbyte*)scratch);
        if((*env)->ExceptionCheck(env)) return false;
    }
    *length = (size_t)java_length;
    return true;
}

bool copy_bounded_array(
    JNIEnv* env,
    jbyteArray array,
    uint8_t* scratch,
    size_t capacity,
    size_t* length,
    const char* too_large_message) {
    return copy_bounded_array_or_null(
        env, array, scratch, capacity, length, false, too_large_message);
}

jbyteArray make_array(JNIEnv* env, const uint8_t* bytes, size_t length) {
    if(length > INT_MAX) {
        throw_dfc(env, DFC_FFI_BUFFER_TOO_SMALL, 0, 0, "result is too large for Java");
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)length);
    if(result != NULL && length != 0)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, (const jbyte*)bytes);
    return result;
}

jbyteArray make_array_and_wipe(JNIEnv* env, uint8_t* bytes, size_t length, size_t capacity) {
    jbyteArray result = make_array(env, bytes, length);
    dfc_ffi_secure_zero(bytes, capacity);
    return result;
}

void put_u32_be(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

int load_credential(JNIEnv* env, jbyteArray content, DfcFfiCredential** credential) {
    size_t length = 0;
    uint8_t* bytes = copy_array(env, content, &length, false);
    if((*env)->ExceptionCheck(env)) return 0;
    DfcFfiError error = {0};
    int32_t status = dfc_ffi_credential_load(bytes, length, credential, &error);
    secure_free(bytes, length);
    if(status != DFC_FFI_OK) {
        throw_dfc(env, status, error.line, 0, error.message);
        return 0;
    }
    return 1;
}

jbyteArray encode_credential(JNIEnv* env, const DfcFfiCredential* credential) {
    size_t length = 0;
    int32_t status = dfc_ffi_credential_encode(credential, NULL, 0, &length);
    if(status != DFC_FFI_OK) {
        throw_dfc(env, status, 0, 0, "could not size encoded credential");
        return NULL;
    }
    size_t capacity = length;
    uint8_t* bytes = capacity == 0 ? NULL : malloc(capacity);
    if(length != 0 && bytes == NULL) {
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return NULL;
    }
    status = dfc_ffi_credential_encode(credential, bytes, capacity, &length);
    if(status != DFC_FFI_OK) {
        secure_free(bytes, capacity);
        throw_dfc(env, status, 0, 0, "could not encode credential");
        return NULL;
    }
    jbyteArray result = make_array(env, bytes, length);
    secure_free(bytes, capacity);
    return result;
}

int32_t scripted_random(void* context, uint8_t* buffer, size_t length) {
    JniPicc* wrapper = context;
    size_t available = wrapper->random_offset < wrapper->random_len ?
                           wrapper->random_len - wrapper->random_offset :
                           0;
    if(available < length) return DFC_FFI_RANDOM_FAILED;
    if(length != 0) memcpy(buffer, wrapper->random + wrapper->random_offset, length);
    wrapper->random_offset += length;
    return DFC_FFI_OK;
}

JniPicc* picc_handle(JNIEnv* env, jlong handle) {
    JniPicc* wrapper = (JniPicc*)(uintptr_t)handle;
    if(wrapper == NULL)
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid virtual PICC handle");
    return wrapper;
}

int32_t picc_exchange(
    JniPicc* wrapper,
    const uint8_t* input,
    size_t input_len,
    bool frame,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    return frame ?
               dfc_ffi_picc_frame_exchange(
                   wrapper->picc, input, input_len, response, response_capacity, response_len) :
               dfc_ffi_picc_exchange(
                   wrapper->picc, input, input_len, response, response_capacity, response_len);
}

JniReader* reader_handle(JNIEnv* env, jlong handle) {
    JniReader* wrapper = (JniReader*)(uintptr_t)handle;
    if(wrapper == NULL) throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid reader handle");
    return wrapper;
}

// Narrow a caller jint to a byte without wrapping; throws DfcException(INVALID_ARGUMENT).
bool jint_to_u8(JNIEnv* env, jint value, const char* name, uint8_t* out) {
    if(value < 0 || value > 0xff) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, name);
        return false;
    }
    *out = (uint8_t)value;
    return true;
}

bool jint_to_u32(JNIEnv* env, jint value, const char* name, uint32_t* out) {
    if(value < 0) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, name);
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

bool jlong_to_u32(JNIEnv* env, jlong value, const char* name, uint32_t* out) {
    if(value < 0 || (uint64_t)value > UINT32_MAX) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, name);
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

bool jlong_to_size(JNIEnv* env, jlong value, const char* name, size_t* out) {
    if(value < 0 || (uint64_t)value > SIZE_MAX) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, name);
        return false;
    }
    *out = (size_t)value;
    return true;
}

DfcFfiTransactionMacVerifier* transaction_mac_handle(JNIEnv* env, jlong handle) {
    DfcFfiTransactionMacVerifier* verifier = (DfcFfiTransactionMacVerifier*)(uintptr_t)handle;
    if(verifier == NULL)
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid transaction MAC handle");
    return verifier;
}

void reader_clear_pending(JniReader* wrapper) {
    secure_free(wrapper->pending_data, wrapper->pending_data_len);
    wrapper->pending_data = NULL;
    wrapper->pending_data_len = 0;
}

JNIEXPORT jint JNICALL Java_com_cindersocket_dfc_DfcNative_abiVersion(JNIEnv* env, jclass type) {
    (void)env;
    (void)type;
    return (jint)dfc_ffi_abi_version();
}

JNIEXPORT jlong JNICALL
    Java_com_cindersocket_dfc_DfcNative_layoutFingerprint(JNIEnv* env, jclass type) {
    (void)env;
    (void)type;
    return (jlong)dfc_ffi_layout_fingerprint();
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_an10922Diversify(
    JNIEnv* env,
    jclass type,
    jint algorithm,
    jbyteArray master,
    jbyteArray input) {
    (void)type;
    uint32_t algorithm_id = 0;
    if(!jint_to_u32(env, algorithm, "algorithm out of range", &algorithm_id)) return NULL;
    uint8_t master_bytes[DFC_MAX_KEY_LEN];
    uint8_t input_bytes[JNI_AN10922_INPUT_MAX];
    size_t master_len = 0, input_len = 0;
    if(!copy_bounded_array(
           env, master, master_bytes, sizeof(master_bytes), &master_len, "master key is too large") ||
       !copy_bounded_array(
           env,
           input,
           input_bytes,
           sizeof(input_bytes),
           &input_len,
           "diversification input is too large"))
        goto cleanup;
    uint8_t output[24] = {0};
    size_t output_len = 0;
    int32_t status = dfc_ffi_an10922_diversify(
        algorithm_id,
        master_bytes,
        master_len,
        input_bytes,
        input_len,
        output,
        sizeof(output),
        &output_len);
    dfc_ffi_secure_zero(master_bytes, sizeof(master_bytes));
    dfc_ffi_secure_zero(input_bytes, sizeof(input_bytes));
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(output, sizeof(output));
        throw_dfc(env, status, 0, 0, "key diversification failed");
        return NULL;
    }
    return make_array_and_wipe(env, output, output_len, sizeof(output));
cleanup:
    dfc_ffi_secure_zero(master_bytes, sizeof(master_bytes));
    dfc_ffi_secure_zero(input_bytes, sizeof(input_bytes));
    return NULL;
}

typedef int32_t (*JniFixedDecoder)(const uint8_t*, size_t, uint8_t*, size_t);

static jbyteArray
    decode_fixed(JNIEnv* env, jbyteArray response, size_t output_len, JniFixedDecoder decoder) {
    uint8_t response_bytes[JNI_FIXED_RESPONSE_MAX];
    size_t response_len = 0;
    if(!copy_bounded_array(
           env,
           response,
           response_bytes,
           sizeof(response_bytes),
           &response_len,
           "response is too large")) {
        dfc_ffi_secure_zero(response_bytes, sizeof(response_bytes));
        return NULL;
    }
    uint8_t output[DFC_FFI_RESPONSE_FILE_SETTINGS_SIZE] = {0};
    int32_t status = decoder(response_bytes, response_len, output, output_len);
    dfc_ffi_secure_zero(response_bytes, sizeof(response_bytes));
    if(status != DFC_FFI_RESPONSE_OK) {
        dfc_ffi_secure_zero(output, sizeof(output));
        throw_dfc(env, status, 0, 0, "response decode failed");
        return NULL;
    }
    return make_array_and_wipe(env, output, output_len, sizeof(output));
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeVersion(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    return decode_fixed(
        env, response, DFC_FFI_RESPONSE_VERSION_SIZE, dfc_ffi_response_decode_version);
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeFileSettings(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    return decode_fixed(
        env, response, DFC_FFI_RESPONSE_FILE_SETTINGS_SIZE, dfc_ffi_response_decode_file_settings);
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeKeySettings(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    return decode_fixed(
        env, response, DFC_FFI_RESPONSE_KEY_SETTINGS_SIZE, dfc_ffi_response_decode_key_settings);
}

typedef int32_t (*JniListDecoder)(const uint8_t*, size_t, uint8_t*, size_t, size_t*);

static jbyteArray decode_list(JNIEnv* env, jbyteArray response, JniListDecoder decoder) {
    size_t response_len = 0;
    uint8_t* response_bytes = copy_array(env, response, &response_len, false);
    if((*env)->ExceptionCheck(env)) return NULL;
    size_t output_len = 0;
    // List decoders never expand their input and support in-place output. Reuse
    // the JNI copy so a response needs one native allocation instead of two.
    int32_t status =
        decoder(response_bytes, response_len, response_bytes, response_len, &output_len);
    if(status != DFC_FFI_RESPONSE_OK) {
        secure_free(response_bytes, response_len);
        throw_dfc(env, status, 0, 0, "response decode failed");
        return NULL;
    }
    if(output_len > response_len) {
        secure_free(response_bytes, response_len);
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid decoded response length");
        return NULL;
    }
    jbyteArray result = make_array(env, response_bytes, output_len);
    secure_free(response_bytes, response_len);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeApplicationIds(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    return decode_list(env, response, dfc_ffi_response_decode_application_ids);
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeFileIds(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    return decode_list(env, response, dfc_ffi_response_decode_file_ids);
}

JNIEXPORT jint JNICALL Java_com_cindersocket_dfc_DfcNative_responseDecodeKeyVersion(
    JNIEnv* env,
    jclass type,
    jbyteArray response) {
    (void)type;
    uint8_t response_bytes[1];
    size_t response_len = 0;
    if(!copy_bounded_array(
           env,
           response,
           response_bytes,
           sizeof(response_bytes),
           &response_len,
           "key-version response is too large")) {
        dfc_ffi_secure_zero(response_bytes, sizeof(response_bytes));
        return 0;
    }
    uint8_t version = 0;
    int32_t status = dfc_ffi_response_decode_key_version(response_bytes, response_len, &version);
    dfc_ffi_secure_zero(response_bytes, sizeof(response_bytes));
    if(status != DFC_FFI_RESPONSE_OK) {
        throw_dfc(env, status, 0, 0, "response decode failed");
        return 0;
    }
    return version;
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_sdmVerify(
    JNIEnv* env,
    jclass type,
    jbyteArray message,
    jint fields,
    jlong plain_uid_offset,
    jlong plain_uid_len,
    jlong plain_counter_offset,
    jlong encrypted_picc_offset,
    jlong encrypted_picc_len,
    jlong encrypted_file_offset,
    jlong encrypted_file_len,
    jlong mac_input_offset,
    jlong mac_offset,
    jbyteArray meta_key,
    jbyteArray file_key) {
    (void)type;
    uint32_t field_flags = 0;
    size_t values[9] = {0};
    jlong java_values[9] = {
        plain_uid_offset,
        plain_uid_len,
        plain_counter_offset,
        encrypted_picc_offset,
        encrypted_picc_len,
        encrypted_file_offset,
        encrypted_file_len,
        mac_input_offset,
        mac_offset};
    if(!jint_to_u32(env, fields, "SDM fields out of range", &field_flags)) return NULL;
    for(size_t i = 0; i < 9; i++)
        if(!jlong_to_size(env, java_values[i], "SDM offset or length out of range", &values[i]))
            return NULL;
    size_t message_len = 0, meta_len = 0, file_len = 0;
    uint8_t* message_bytes = copy_array(env, message, &message_len, false);
    uint8_t meta_bytes[DFC_AES_KEY_LENGTH];
    uint8_t file_bytes[DFC_AES_KEY_LENGTH];
    bool copied_meta = copy_bounded_array_or_null(
        env,
        meta_key,
        meta_bytes,
        sizeof(meta_bytes),
        &meta_len,
        true,
        "SDM metadata key is too large");
    bool copied_file =
        copied_meta &&
        copy_bounded_array(
            env, file_key, file_bytes, sizeof(file_bytes), &file_len, "SDM file key is too large");
    if((*env)->ExceptionCheck(env) || !copied_file || file_len != DFC_AES_KEY_LENGTH ||
       (meta_key != NULL && meta_len != DFC_AES_KEY_LENGTH)) {
        secure_free(message_bytes, message_len);
        dfc_ffi_secure_zero(meta_bytes, sizeof(meta_bytes));
        dfc_ffi_secure_zero(file_bytes, sizeof(file_bytes));
        if(!(*env)->ExceptionCheck(env))
            throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "SDM keys must be 16 bytes");
        return NULL;
    }
    if(values[6] > message_len || values[6] > (size_t)INT32_MAX - DFC_FFI_SDM_RESULT_SIZE) {
        secure_free(message_bytes, message_len);
        dfc_ffi_secure_zero(meta_bytes, sizeof(meta_bytes));
        dfc_ffi_secure_zero(file_bytes, sizeof(file_bytes));
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "encrypted file range is too large");
        return NULL;
    }
    size_t decrypted_len = values[6] / 2;
    size_t packed_len = DFC_FFI_SDM_RESULT_SIZE + decrypted_len;
    uint8_t* packed = calloc(1, packed_len);
    if(!packed) {
        secure_free(message_bytes, message_len);
        dfc_ffi_secure_zero(meta_bytes, sizeof(meta_bytes));
        dfc_ffi_secure_zero(file_bytes, sizeof(file_bytes));
        throw_dfc(env, DFC_FFI_OUT_OF_MEMORY, 0, 0, "out of memory");
        return NULL;
    }
    size_t required = 0;
    int32_t status = dfc_ffi_sdm_verify_ascii(
        message_bytes,
        message_len,
        field_flags,
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        values[8],
        meta_key != NULL ? meta_bytes : NULL,
        file_bytes,
        decrypted_len ? packed + DFC_FFI_SDM_RESULT_SIZE : NULL,
        decrypted_len,
        &required,
        packed,
        DFC_FFI_SDM_RESULT_SIZE);
    secure_free(message_bytes, message_len);
    dfc_ffi_secure_zero(meta_bytes, sizeof(meta_bytes));
    dfc_ffi_secure_zero(file_bytes, sizeof(file_bytes));
    if(status != DFC_FFI_SDM_OK || required != decrypted_len) {
        secure_free(packed, packed_len);
        throw_dfc(env, status, 0, 0, "SDM verification failed");
        return NULL;
    }
    jbyteArray result = make_array(env, packed, packed_len);
    secure_free(packed, packed_len);
    return result;
}

JNIEXPORT jlong JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacCreate(
    JNIEnv* env,
    jclass type,
    jint capacity,
    jbyteArray key,
    jbyteArray uid,
    jlong counter) {
    (void)type;
    uint32_t counter_value = 0;
    if(capacity <= 0 || !jlong_to_u32(env, counter, "counter out of range", &counter_value)) {
        if(capacity <= 0 && !(*env)->ExceptionCheck(env))
            throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "capacity must be positive");
        return 0;
    }
    uint8_t key_bytes[DFC_AES_KEY_LENGTH];
    uint8_t uid_bytes[DFC_DESFIRE_UID_LEN];
    size_t key_len = 0, uid_len = 0;
    if(!copy_bounded_array(
           env, key, key_bytes, sizeof(key_bytes), &key_len, "transaction MAC key is too large") ||
       !copy_bounded_array(
           env, uid, uid_bytes, sizeof(uid_bytes), &uid_len, "transaction MAC UID is too large"))
        goto cleanup;
    if(key_len != DFC_AES_KEY_LENGTH || (uid_len != 4 && uid_len != DFC_DESFIRE_UID_LEN)) {
        throw_dfc(
            env,
            DFC_FFI_INVALID_ARGUMENT,
            0,
            0,
            "transaction MAC key must be 16 bytes and UID must be 4 or 7 bytes");
        goto cleanup;
    }
    DfcFfiTransactionMacVerifier* verifier = NULL;
    int32_t status = dfc_ffi_transaction_mac_verifier_new(
        (size_t)capacity, key_bytes, uid_bytes, uid_len, counter_value, &verifier);
    dfc_ffi_secure_zero(key_bytes, sizeof(key_bytes));
    dfc_ffi_secure_zero(uid_bytes, sizeof(uid_bytes));
    if(status != DFC_FFI_TRANSACTION_MAC_OK) {
        throw_dfc(env, status, 0, 0, "transaction MAC initialization failed");
        return 0;
    }
    return (jlong)(uintptr_t)verifier;
cleanup:
    dfc_ffi_secure_zero(key_bytes, sizeof(key_bytes));
    dfc_ffi_secure_zero(uid_bytes, sizeof(uid_bytes));
    return 0;
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_transactionMacFree(JNIEnv* env, jclass type, jlong handle) {
    (void)env;
    (void)type;
    dfc_ffi_transaction_mac_verifier_free((DfcFfiTransactionMacVerifier*)(uintptr_t)handle);
}

static bool transaction_mac_status(JNIEnv* env, int32_t status) {
    if(status == DFC_FFI_TRANSACTION_MAC_OK) return true;
    throw_dfc(env, status, 0, 0, "transaction MAC operation failed");
    return false;
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacAddData(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint command,
    jint file_number,
    jlong offset,
    jlong length,
    jbyteArray data) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    uint8_t command_id = 0, file_id = 0;
    uint32_t offset_value = 0, length_value = 0;
    if(!verifier || !jint_to_u8(env, command, "command out of range", &command_id) ||
       !jint_to_u8(env, file_number, "file number out of range", &file_id) ||
       !jlong_to_u32(env, offset, "offset out of range", &offset_value) ||
       !jlong_to_u32(env, length, "length out of range", &length_value))
        return;
    size_t data_len = 0;
    uint8_t* bytes = copy_array(env, data, &data_len, false);
    if((*env)->ExceptionCheck(env)) return;
    int32_t status = dfc_ffi_transaction_mac_add_data(
        verifier, command_id, file_id, offset_value, length_value, bytes, data_len);
    secure_free(bytes, data_len);
    transaction_mac_status(env, status);
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacAddRecord(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint command,
    jint file_number,
    jlong record_number,
    jlong offset,
    jlong length,
    jbyteArray data) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    uint8_t command_id = 0, file_id = 0;
    uint32_t record_value = 0, offset_value = 0, length_value = 0;
    if(!verifier || !jint_to_u8(env, command, "command out of range", &command_id) ||
       !jint_to_u8(env, file_number, "file number out of range", &file_id) ||
       !jlong_to_u32(env, record_number, "record number out of range", &record_value) ||
       !jlong_to_u32(env, offset, "offset out of range", &offset_value) ||
       !jlong_to_u32(env, length, "length out of range", &length_value))
        return;
    size_t data_len = 0;
    uint8_t* bytes = copy_array(env, data, &data_len, false);
    if((*env)->ExceptionCheck(env)) return;
    int32_t status = dfc_ffi_transaction_mac_add_record_update(
        verifier, command_id, file_id, record_value, offset_value, length_value, bytes, data_len);
    secure_free(bytes, data_len);
    transaction_mac_status(env, status);
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacAddValue(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint command,
    jint file_number,
    jlong value) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    uint8_t command_id = 0, file_id = 0;
    uint32_t amount = 0;
    if(!verifier || !jint_to_u8(env, command, "command out of range", &command_id) ||
       !jint_to_u8(env, file_number, "file number out of range", &file_id) ||
       !jlong_to_u32(env, value, "value out of range", &amount))
        return;
    transaction_mac_status(
        env, dfc_ffi_transaction_mac_add_value(verifier, command_id, file_id, amount));
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacAddClearRecord(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jint file_number) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    uint8_t file_id = 0;
    if(!verifier || !jint_to_u8(env, file_number, "file number out of range", &file_id)) return;
    transaction_mac_status(env, dfc_ffi_transaction_mac_add_clear_record(verifier, file_id));
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacAddReaderId(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray current,
    jbyteArray previous) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    if(!verifier) return;
    uint8_t current_bytes[DFC_TRANSACTION_READER_ID_LENGTH];
    uint8_t previous_bytes[DFC_TRANSACTION_READER_ID_LENGTH];
    size_t current_len = 0, previous_len = 0;
    if(!copy_bounded_array(
           env,
           current,
           current_bytes,
           sizeof(current_bytes),
           &current_len,
           "current reader ID is too large") ||
       !copy_bounded_array(
           env,
           previous,
           previous_bytes,
           sizeof(previous_bytes),
           &previous_len,
           "previous reader ID is too large") ||
       current_len != sizeof(current_bytes) || previous_len != sizeof(previous_bytes)) {
        dfc_ffi_secure_zero(current_bytes, sizeof(current_bytes));
        dfc_ffi_secure_zero(previous_bytes, sizeof(previous_bytes));
        if(!(*env)->ExceptionCheck(env))
            throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "reader IDs must be 16 bytes");
        return;
    }
    int32_t status =
        dfc_ffi_transaction_mac_add_reader_id(verifier, current_bytes, previous_bytes);
    dfc_ffi_secure_zero(current_bytes, sizeof(current_bytes));
    dfc_ffi_secure_zero(previous_bytes, sizeof(previous_bytes));
    transaction_mac_status(env, status);
}

JNIEXPORT jboolean JNICALL Java_com_cindersocket_dfc_DfcNative_transactionMacVerify(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray mac) {
    (void)type;
    DfcFfiTransactionMacVerifier* verifier = transaction_mac_handle(env, handle);
    if(!verifier) return JNI_FALSE;
    uint8_t mac_bytes[DFC_WIRE_MAC_LENGTH];
    size_t mac_len = 0;
    if(!copy_bounded_array(
           env, mac, mac_bytes, sizeof(mac_bytes), &mac_len, "transaction MAC is too large") ||
       mac_len != sizeof(mac_bytes)) {
        dfc_ffi_secure_zero(mac_bytes, sizeof(mac_bytes));
        if(!(*env)->ExceptionCheck(env))
            throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "transaction MAC must be 8 bytes");
        return JNI_FALSE;
    }
    uint8_t verified = 0;
    int32_t status = dfc_ffi_transaction_mac_verify(verifier, mac_bytes, &verified);
    dfc_ffi_secure_zero(mac_bytes, sizeof(mac_bytes));
    if(!transaction_mac_status(env, status)) return JNI_FALSE;
    return verified ? JNI_TRUE : JNI_FALSE;
}
