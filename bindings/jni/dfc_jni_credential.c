#include "dfc_jni_internal.h"

#include <stdlib.h>

#include "dfc_ffi_layout.h"

JNIEXPORT jlong JNICALL
    Java_com_cindersocket_dfc_DfcNative_expectedLayoutFingerprint(JNIEnv* env, jclass type) {
    (void)env;
    (void)type;
    return (jlong)dfc_ffi_expected_layout_fingerprint();
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
