#pragma once
#include <cstdint>

struct CipherOperation
{
    uint8_t* plaintext;
    uint8_t* ciphertext;

    uint8_t* key;
    uint8_t* iv;
    uint8_t* aad; /* used for AEAD crypto operation */
    uint8_t* tag; /* used for AEAD crypto operation */

    uint32_t ciphertextLength;
    uint32_t plaintextLength;

    uint16_t keyLength;
    uint16_t ivLength;
    uint16_t aadLength; /* used for AEAD crypto operation */
    uint16_t tagLength; /* used for AEAD crypto operation */
};