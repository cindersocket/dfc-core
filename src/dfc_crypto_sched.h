#pragma once

/*
 * One-shot block-cipher schedules for callers that encrypt many blocks under
 * the same key. Scheduling per block repeats the same key expansion, which
 * dominates CMAC and the legacy per-block DES loops.
 *
 * These are internal helpers, not part of the library interface. They are
 * static inline so a build does not export them. Define DFC_NEED_AES_SCHED
 * and/or DFC_NEED_DES_SCHED before including this header.
 *
 * A single-block encrypt here is the same operation the CBC helpers perform
 * with a zero IV: ciphertext = E(plaintext). Callers that need chaining XOR
 * the previous ciphertext themselves, matching the previous CBC calls.
 */

#include "dfc_crypto.h"

#include <string.h>

#if defined(DFC_CRYPTO_BACKEND_MBEDTLS) && defined(DFC_CRYPTO_BACKEND_TINY)
#error "Select only one DFC crypto backend"
#elif !defined(DFC_CRYPTO_BACKEND_MBEDTLS) && !defined(DFC_CRYPTO_BACKEND_TINY)
#define DFC_CRYPTO_BACKEND_MBEDTLS 1
#endif

#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#else
#include <tiny_crypto/aes.h>
#include <tiny_crypto/des.h>
#endif

#if defined(DFC_NEED_AES_SCHED)

typedef struct {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    mbedtls_aes_context ctx;
#else
    struct TC_AES_ctx ctx;
#endif
} DfcAesEnc;

static inline bool dfc_aes_enc_begin(DfcAesEnc* sched, const uint8_t* key) {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    mbedtls_aes_init(&sched->ctx);
    if(mbedtls_aes_setkey_enc(&sched->ctx, key, 128) != 0) {
        mbedtls_aes_free(&sched->ctx);
        return false;
    }
    return true;
#else
    return TC_AES_init(&sched->ctx, (TC_bytes){key, 16}) == TC_OK;
#endif
}

/* Encrypt one independent block. Equivalent to CBC with a zero IV. */
static inline bool dfc_aes_enc_block(DfcAesEnc* sched, const uint8_t in[16], uint8_t out[16]) {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    return mbedtls_aes_crypt_ecb(&sched->ctx, MBEDTLS_AES_ENCRYPT, in, out) == 0;
#elif TC_AES_ENABLE_ECB
    if(out != in) memcpy(out, in, 16);
    return TC_AES_ECB_encrypt(&sched->ctx.key, (TC_buffer){out, 16}) == TC_OK;
#else
    uint8_t iv[16] = {0};
    if(TC_AES_set_iv(&sched->ctx, (TC_bytes){iv, 16}) != TC_OK) return false;
    if(out != in) memcpy(out, in, 16);
    return TC_AES_CBC_encrypt(&sched->ctx, (TC_buffer){out, 16}) == TC_OK;
#endif
}

static inline void dfc_aes_enc_end(DfcAesEnc* sched) {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    mbedtls_aes_free(&sched->ctx);
#else
    TC_AES_ctx_clear(&sched->ctx);
#endif
}

#endif /* DFC_NEED_AES_SCHED */

#if defined(DFC_NEED_DES_SCHED)

typedef struct {
    bool encrypt;
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    bool triple;
    union {
        mbedtls_des_context des;
        mbedtls_des3_context des3;
    } u;
#else
    struct TC_DES_ctx ctx;
#endif
} DfcDesSched;

static inline bool
    dfc_des_sched_begin(DfcDesSched* sched, bool encrypt, const uint8_t* key, size_t key_len) {
    if(key_len != 8 && key_len != 16 && key_len != 24) return false;
    sched->encrypt = encrypt;
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    sched->triple = key_len != 8;
    int result;
    if(!sched->triple) {
        mbedtls_des_init(&sched->u.des);
        result = encrypt ? mbedtls_des_setkey_enc(&sched->u.des, key) :
                           mbedtls_des_setkey_dec(&sched->u.des, key);
        if(result != 0) mbedtls_des_free(&sched->u.des);
    } else {
        mbedtls_des3_init(&sched->u.des3);
        if(key_len == 24) {
            result = encrypt ? mbedtls_des3_set3key_enc(&sched->u.des3, key) :
                               mbedtls_des3_set3key_dec(&sched->u.des3, key);
        } else {
            result = encrypt ? mbedtls_des3_set2key_enc(&sched->u.des3, key) :
                               mbedtls_des3_set2key_dec(&sched->u.des3, key);
        }
        if(result != 0) mbedtls_des3_free(&sched->u.des3);
    }
    return result == 0;
#else
    return TC_DES_init(&sched->ctx, (TC_bytes){key, key_len}) == TC_OK;
#endif
}

static inline bool dfc_des_sched_block(DfcDesSched* sched, const uint8_t in[8], uint8_t out[8]) {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    if(!sched->triple) return mbedtls_des_crypt_ecb(&sched->u.des, in, out) == 0;
    return mbedtls_des3_crypt_ecb(&sched->u.des3, in, out) == 0;
#else
    uint8_t block[8];
    memcpy(block, in, 8);
    TC_status result = sched->encrypt ? TC_DES_ECB_encrypt(&sched->ctx, (TC_buffer){block, 8}) :
                                        TC_DES_ECB_decrypt(&sched->ctx, (TC_buffer){block, 8});
    if(result != TC_OK) return false;
    memcpy(out, block, 8);
    return true;
#endif
}

static inline void dfc_des_sched_end(DfcDesSched* sched) {
#if defined(DFC_CRYPTO_BACKEND_MBEDTLS)
    if(sched->triple) mbedtls_des3_free(&sched->u.des3);
    else mbedtls_des_free(&sched->u.des);
#else
    TC_DES_ctx_clear(&sched->ctx);
#endif
}

#endif /* DFC_NEED_DES_SCHED */
