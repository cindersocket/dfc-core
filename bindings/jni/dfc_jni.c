#include <jni.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dfc_ffi.h"

#define JNI_PICC_RESPONSE_MAX 256u
#define JNI_READER_FRAME_MAX  600u

typedef struct {
    DfcFfiPicc* picc;
    uint8_t* random;
    size_t random_len;
    size_t random_offset;
} JniPicc;

typedef struct {
    DfcFfiReaderSession* session;
    DfcFfiReaderExchange* exchange;
    uint8_t* pending_data;
    size_t pending_data_len;
} JniReader;

static void
    throw_dfc(JNIEnv* env, int32_t status, uint32_t line, uint8_t card_status, const char* message) {
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

static void secure_free(void* buffer, size_t length) {
    if(buffer == NULL) return;
    dfc_ffi_secure_zero(buffer, length);
    free(buffer);
}

static uint8_t* copy_array(JNIEnv* env, jbyteArray array, size_t* length, bool nullable) {
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

static jbyteArray make_array(JNIEnv* env, const uint8_t* bytes, size_t length) {
    if(length > INT_MAX) {
        throw_dfc(env, DFC_FFI_BUFFER_TOO_SMALL, 0, 0, "result is too large for Java");
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)length);
    if(result != NULL && length != 0)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, (const jbyte*)bytes);
    return result;
}

static jbyteArray
    make_array_and_wipe(JNIEnv* env, uint8_t* bytes, size_t length, size_t capacity) {
    jbyteArray result = make_array(env, bytes, length);
    dfc_ffi_secure_zero(bytes, capacity);
    return result;
}

static void put_u32_be(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static int load_credential(JNIEnv* env, jbyteArray content, DfcFfiCredential** credential) {
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

static jbyteArray encode_credential(JNIEnv* env, const DfcFfiCredential* credential) {
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

static void scripted_random(void* context, uint8_t* buffer, size_t length) {
    JniPicc* wrapper = context;
    size_t available = wrapper->random_offset < wrapper->random_len ?
                           wrapper->random_len - wrapper->random_offset :
                           0;
    size_t copy = available < length ? available : length;
    if(copy != 0) memcpy(buffer, wrapper->random + wrapper->random_offset, copy);
    if(copy < length) memset(buffer + copy, 0, length - copy);
    wrapper->random_offset += copy;
}

static JniPicc* picc_handle(JNIEnv* env, jlong handle) {
    JniPicc* wrapper = (JniPicc*)(uintptr_t)handle;
    if(wrapper == NULL)
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid virtual PICC handle");
    return wrapper;
}

static JniReader* reader_handle(JNIEnv* env, jlong handle) {
    JniReader* wrapper = (JniReader*)(uintptr_t)handle;
    if(wrapper == NULL) throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "invalid reader handle");
    return wrapper;
}

static void reader_clear_pending(JniReader* wrapper) {
    secure_free(wrapper->pending_data, wrapper->pending_data_len);
    wrapper->pending_data = NULL;
    wrapper->pending_data_len = 0;
}

JNIEXPORT jint JNICALL Java_com_cindersocket_dfc_DfcNative_abiVersion(JNIEnv* env, jclass type) {
    (void)env;
    (void)type;
    return (jint)dfc_ffi_abi_version();
}

JNIEXPORT jlong JNICALL Java_com_cindersocket_dfc_DfcNative_capabilities(JNIEnv* env, jclass type) {
    (void)env;
    (void)type;
    DfcFfiCapabilities capabilities = {0};
    dfc_ffi_capabilities(&capabilities);
    const uint8_t* flags = &capabilities.generation_ev1;
    size_t count = offsetof(DfcFfiCapabilities, max_applications) -
                   offsetof(DfcFfiCapabilities, generation_ev1);
    uint64_t bits = 0;
    for(size_t i = 0; i < count && i < 64; i++)
        if(flags[i] != 0) bits |= UINT64_C(1) << i;
    return (jlong)bits;
}

JNIEXPORT jbyteArray JNICALL
    Java_com_cindersocket_dfc_DfcNative_credentialParse(JNIEnv* env, jclass type, jbyteArray text) {
    (void)type;
    size_t length = 0;
    uint8_t* bytes = copy_array(env, text, &length, false);
    if((*env)->ExceptionCheck(env)) return NULL;
    DfcFfiCredential* credential = NULL;
    DfcFfiError error = {0};
    int32_t status =
        dfc_ffi_credential_parse_text((const char*)bytes, length, &credential, &error);
    secure_free(bytes, length);
    if(status != DFC_FFI_OK) {
        throw_dfc(env, status, error.line, 0, error.message);
        return NULL;
    }
    jbyteArray result = encode_credential(env, credential);
    dfc_ffi_credential_free(credential);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_credentialLoad(
    JNIEnv* env,
    jclass type,
    jbyteArray content) {
    (void)type;
    DfcFfiCredential* credential = NULL;
    if(!load_credential(env, content, &credential)) return NULL;
    jbyteArray result = encode_credential(env, credential);
    dfc_ffi_credential_free(credential);
    return result;
}

JNIEXPORT jstring JNICALL Java_com_cindersocket_dfc_DfcNative_credentialText(
    JNIEnv* env,
    jclass type,
    jbyteArray content) {
    (void)type;
    DfcFfiCredential* credential = NULL;
    if(!load_credential(env, content, &credential)) return NULL;
    size_t length = 0;
    int32_t status = dfc_ffi_credential_write_text(credential, NULL, 0, &length);
    size_t capacity = length + 1;
    char* text = status == DFC_FFI_OK ? malloc(capacity) : NULL;
    if(status == DFC_FFI_OK && text == NULL) status = DFC_FFI_OUT_OF_MEMORY;
    if(status == DFC_FFI_OK)
        status = dfc_ffi_credential_write_text(credential, text, length, &length);
    dfc_ffi_credential_free(credential);
    if(status != DFC_FFI_OK) {
        secure_free(text, capacity);
        throw_dfc(env, status, 0, 0, "could not write credential text");
        return NULL;
    }
    text[length] = '\0';
    jstring result = (*env)->NewStringUTF(env, text);
    secure_free(text, capacity);
    return result;
}

JNIEXPORT void JNICALL Java_com_cindersocket_dfc_DfcNative_credentialValidate(
    JNIEnv* env,
    jclass type,
    jbyteArray content) {
    (void)type;
    DfcFfiCredential* credential = NULL;
    if(!load_credential(env, content, &credential)) return;
    int32_t status = dfc_ffi_credential_validate(credential);
    dfc_ffi_credential_free(credential);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "credential validation failed");
}

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
        wrapper->random = copy_array(env, random_script, &wrapper->random_len, true);
        if((*env)->ExceptionCheck(env)) {
            secure_free(wrapper, sizeof(*wrapper));
            dfc_ffi_credential_free(credential);
            return 0;
        }
    }
    int32_t status = dfc_ffi_picc_create(
        credential, random_script == NULL ? NULL : scripted_random, wrapper, &wrapper->picc);
    dfc_ffi_credential_free(credential);
    if(status != DFC_FFI_OK) {
        secure_free(wrapper->random, wrapper->random_len);
        secure_free(wrapper, sizeof(*wrapper));
        throw_dfc(env, status, 0, 0, "could not create virtual PICC");
        return 0;
    }
    return (jlong)(uintptr_t)wrapper;
}

JNIEXPORT void JNICALL
    Java_com_cindersocket_dfc_DfcNative_piccFree(JNIEnv* env, jclass type, jlong handle) {
    (void)env;
    (void)type;
    JniPicc* wrapper = (JniPicc*)(uintptr_t)handle;
    if(wrapper == NULL) return;
    dfc_ffi_picc_free(wrapper->picc);
    secure_free(wrapper->random, wrapper->random_len);
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
    uint8_t packed[1 + 10 + 1 + 2 + 1 + 1 + 20];
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
    uint8_t packed[18];
    size_t offset = 0;
    packed[offset++] = (uint8_t)snapshot.selected;
    put_u32_be(packed + offset, snapshot.selected_application_index);
    offset += 4;
    memcpy(packed + offset, snapshot.selected_aid, 3);
    offset += 3;
    packed[offset++] = snapshot.dirty;
    packed[offset++] = snapshot.auth_mode;
    packed[offset++] = snapshot.auth_key_no;
    put_u32_be(packed + offset, snapshot.ev2_command_counter);
    offset += 4;
    packed[offset++] = snapshot.ev2_active;
    packed[offset++] = snapshot.virtual_card_selected;
    packed[offset++] = snapshot.proximity_verified;
    jbyteArray result = make_array_and_wipe(env, packed, offset, sizeof(packed));
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
    uint8_t response[JNI_PICC_RESPONSE_MAX];
    size_t response_len = 0;
    int32_t status =
        frame ?
            dfc_ffi_picc_frame_exchange(
                wrapper->picc, input_bytes, input_len, response, sizeof(response), &response_len) :
            dfc_ffi_picc_exchange(
                wrapper->picc, input_bytes, input_len, response, sizeof(response), &response_len);
    secure_free(input_bytes, input_len);
    if(status != DFC_FFI_OK) {
        dfc_ffi_secure_zero(response, sizeof(response));
        throw_dfc(env, status, 0, 0, "virtual PICC exchange failed");
        return NULL;
    }
    return make_array_and_wipe(env, response, response_len, sizeof(response));
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
    int32_t status = dfc_ffi_picc_advance_time(wrapper->picc, (uint32_t)milliseconds);
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
    size_t length = 0;
    uint8_t* bytes = copy_array(env, data, &length, false);
    if((*env)->ExceptionCheck(env)) return;
    reader_clear_pending(wrapper);
    wrapper->pending_data = bytes;
    wrapper->pending_data_len = length;
    int32_t status = dfc_ffi_reader_exchange_begin(
        wrapper->exchange,
        wrapper->session,
        (uint32_t)framing,
        (uint8_t)instruction,
        wrapper->pending_data,
        length,
        (uint8_t)communication,
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
    size_t key_len = 0, random_len = 0;
    uint8_t* key_bytes = copy_array(env, key, &key_len, false);
    uint8_t* random_bytes =
        (*env)->ExceptionCheck(env) ? NULL : copy_array(env, random_a, &random_len, false);
    if((*env)->ExceptionCheck(env)) {
        secure_free(key_bytes, key_len);
        return;
    }
    int32_t status = dfc_ffi_reader_authenticate_begin(
        wrapper->exchange,
        wrapper->session,
        (uint32_t)framing,
        (uint8_t)cipher,
        (uint8_t)key_number,
        key_bytes,
        key_len,
        random_bytes,
        random_len);
    secure_free(key_bytes, key_len);
    secure_free(random_bytes, random_len);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "could not begin authentication");
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
    size_t key_len = 0, first_len = 0, second_len = 0;
    uint8_t* key_bytes = copy_array(env, key, &key_len, false);
    uint8_t* first_bytes =
        (*env)->ExceptionCheck(env) ? NULL : copy_array(env, random_first, &first_len, false);
    uint8_t* second_bytes =
        (*env)->ExceptionCheck(env) ? NULL : copy_array(env, random_second, &second_len, false);
    if((*env)->ExceptionCheck(env)) goto cleanup;
    if(first_len != second_len) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "ISO 7816 challenge lengths differ");
        goto cleanup;
    }
    int32_t status = dfc_ffi_reader_authenticate_iso7816_begin(
        wrapper->exchange,
        wrapper->session,
        (uint8_t)key_reference,
        key_bytes,
        key_len,
        (uint8_t)algorithm,
        first_bytes,
        second_bytes,
        first_len);
    if(status != DFC_FFI_OK)
        throw_dfc(env, status, 0, 0, "could not begin ISO 7816 authentication");
cleanup:
    secure_free(key_bytes, key_len);
    secure_free(first_bytes, first_len);
    secure_free(second_bytes, second_len);
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
    size_t key_len = 0, random_len = 0, capabilities_len = 0;
    uint8_t* key_bytes = copy_array(env, key, &key_len, false);
    uint8_t* random_bytes =
        (*env)->ExceptionCheck(env) ? NULL : copy_array(env, random_a, &random_len, false);
    uint8_t* capability_bytes = (*env)->ExceptionCheck(env) ?
                                    NULL :
                                    copy_array(env, capabilities, &capabilities_len, false);
    if((*env)->ExceptionCheck(env)) goto cleanup;
    if(key_len != 16 || random_len != 16) {
        throw_dfc(env, DFC_FFI_INVALID_ARGUMENT, 0, 0, "EV2 keys and challenges must be 16 bytes");
        goto cleanup;
    }
    int32_t status = dfc_ffi_reader_authenticate_ev2_begin(
        wrapper->exchange,
        wrapper->session,
        (uint32_t)framing,
        first ? 1 : 0,
        (uint8_t)key_number,
        key_bytes,
        random_bytes,
        capability_bytes,
        capabilities_len);
    if(status != DFC_FFI_OK) throw_dfc(env, status, 0, 0, "could not begin EV2 authentication");
cleanup:
    secure_free(key_bytes, key_len);
    secure_free(random_bytes, random_len);
    secure_free(capability_bytes, capabilities_len);
}

JNIEXPORT jbyteArray JNICALL Java_com_cindersocket_dfc_DfcNative_readerStep(
    JNIEnv* env,
    jclass type,
    jlong handle,
    jbyteArray answer) {
    (void)type;
    JniReader* wrapper = reader_handle(env, handle);
    if(wrapper == NULL) return NULL;
    size_t answer_len = 0;
    uint8_t* answer_bytes = copy_array(env, answer, &answer_len, true);
    if((*env)->ExceptionCheck(env)) return NULL;
    uint8_t frame[JNI_READER_FRAME_MAX];
    size_t frame_len = 0;
    int32_t status = dfc_ffi_reader_step(
        wrapper->exchange, answer_bytes, answer_len, frame, sizeof(frame), &frame_len);
    secure_free(answer_bytes, answer_len);
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
    uint8_t packed[22];
    size_t offset = 0;
    packed[offset++] = state.auth_mode;
    packed[offset++] = state.key_no;
    put_u32_be(packed + offset, state.ev2_command_counter);
    offset += 4;
    memcpy(packed + offset, state.ev2_transaction_identifier, 4);
    offset += 4;
    memcpy(packed + offset, state.ev2_card_capabilities, 6);
    offset += 6;
    memcpy(packed + offset, state.ev2_reader_capabilities, 6);
    offset += 6;
    jbyteArray result = make_array_and_wipe(env, packed, offset, sizeof(packed));
    dfc_ffi_secure_zero(&state, sizeof(state));
    return result;
}
