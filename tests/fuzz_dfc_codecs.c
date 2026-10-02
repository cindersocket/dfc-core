// libFuzzer property target for accepted credential inputs.

#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_text.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void require(bool condition) {
    if(!condition) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if(size == 0 || size > DFC_TEXT_MAX_SIZE) return 0;

    static DfcCredential source;
    static DfcCredential copy;
    static DfcCredential decoded;
    static DfcCredential parsed;
    static uint8_t binary[DFC_DER_MAX_SIZE];
    static uint8_t binary_again[DFC_DER_MAX_SIZE];
    static char text[DFC_TEXT_MAX_SIZE];
    static char text_again[DFC_TEXT_MAX_SIZE];
    DfcTextError detail = {0};
    if(dfc_credential_load(&source, data, size, &detail) != DfcTextOk) return 0;

    require(dfc_credential_validate_model(&source) == DfcModelOk);
    dfc_credential_copy_model(&copy, &source);
    require(dfc_credential_validate_model(&copy) == DfcModelOk);

    size_t binary_length = 0;
    size_t binary_again_length = 0;
    require(dfc_der_encode(&source, binary, sizeof(binary), &binary_length) == DfcDerOk);
    require(dfc_der_decode(&decoded, binary, binary_length) == DfcDerOk);
    require(
        dfc_der_encode(&decoded, binary_again, sizeof(binary_again), &binary_again_length) ==
        DfcDerOk);
    require(binary_again_length == binary_length);
    require(memcmp(binary_again, binary, binary_length) == 0);

    size_t text_length = 0;
    size_t text_again_length = 0;
    require(dfc_text_write(&source, text, sizeof(text), &text_length) == DfcTextOk);
    require(dfc_text_parse(&parsed, text, text_length, &detail) == DfcTextOk);
    require(
        dfc_text_write(&parsed, text_again, sizeof(text_again), &text_again_length) == DfcTextOk);
    require(text_again_length == text_length);
    require(memcmp(text_again, text, text_length) == 0);

    require(
        dfc_der_encode(&copy, binary_again, sizeof(binary_again), &binary_again_length) ==
        DfcDerOk);
    require(binary_again_length == binary_length);
    require(memcmp(binary_again, binary, binary_length) == 0);

    require(
        dfc_der_encode(&parsed, binary_again, sizeof(binary_again), &binary_again_length) ==
        DfcDerOk);
    require(binary_again_length == binary_length);
    require(memcmp(binary_again, binary, binary_length) == 0);

    require(
        dfc_text_write(&decoded, text_again, sizeof(text_again), &text_again_length) == DfcTextOk);
    require(text_again_length == text_length);
    require(memcmp(text_again, text, text_length) == 0);
    return 0;
}
