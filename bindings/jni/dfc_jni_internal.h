#pragma once

#include <jni.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dfc_ffi.h"

#define JNI_PICC_RESPONSE_INITIAL 256u
#define JNI_READER_FRAME_MAX      600u
#define JNI_AN10922_INPUT_MAX     31u
#define JNI_FIXED_RESPONSE_MAX    DFC_FFI_RESPONSE_VERSION_SIZE

typedef struct {
    DfcFfiPicc* picc;
    uint8_t* random;
    size_t random_len;
    size_t random_offset;
    bool replay_random;
} JniPicc;

typedef struct {
    DfcFfiReaderSession* session;
    DfcFfiReaderExchange* exchange;
    uint8_t* pending_data;
    size_t pending_data_len;
} JniReader;

void throw_dfc(JNIEnv* env, int32_t status, uint32_t line, uint8_t card_status, const char* message);
void secure_free(void* buffer, size_t length);
void clear_replay_random(JniPicc* wrapper);
uint8_t* copy_array(JNIEnv* env, jbyteArray array, size_t* length, bool nullable);
bool copy_bounded_array_or_null(
    JNIEnv* env,
    jbyteArray array,
    uint8_t* scratch,
    size_t capacity,
    size_t* length,
    bool nullable,
    const char* too_large_message);
bool copy_bounded_array(
    JNIEnv* env,
    jbyteArray array,
    uint8_t* scratch,
    size_t capacity,
    size_t* length,
    const char* too_large_message);
jbyteArray make_array(JNIEnv* env, const uint8_t* bytes, size_t length);
jbyteArray make_array_and_wipe(JNIEnv* env, uint8_t* bytes, size_t length, size_t capacity);
void put_u32_be(uint8_t* output, uint32_t value);
int load_credential(JNIEnv* env, jbyteArray content, DfcFfiCredential** credential);
jbyteArray encode_credential(JNIEnv* env, const DfcFfiCredential* credential);
int32_t scripted_random(void* context, uint8_t* buffer, size_t length);
JniPicc* picc_handle(JNIEnv* env, jlong handle);
int32_t picc_exchange(
    JniPicc* wrapper,
    const uint8_t* input,
    size_t input_len,
    bool frame,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len);
JniReader* reader_handle(JNIEnv* env, jlong handle);
bool jint_to_u8(JNIEnv* env, jint value, const char* name, uint8_t* out);
bool jint_to_u32(JNIEnv* env, jint value, const char* name, uint32_t* out);
bool jlong_to_u32(JNIEnv* env, jlong value, const char* name, uint32_t* out);
bool jlong_to_size(JNIEnv* env, jlong value, const char* name, size_t* out);
DfcFfiTransactionMacVerifier* transaction_mac_handle(JNIEnv* env, jlong handle);
void reader_clear_pending(JniReader* wrapper);
