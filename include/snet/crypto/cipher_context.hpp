#pragma once
#include <openssl/evp.h>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

inline CipherCtxPtr AllocateCipherCtx()
{
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    crypto::ThrowIfFalse(ctx);
    return ctx;
}

inline bool CipherIsAEAD(const Cipher* cipher)
{
    return EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
}

inline size_t GetKeyLength(const Cipher* cipher)
{
    return EVP_CIPHER_get_key_length(cipher);
}

inline size_t GetBlockLength(const Cipher* cipher)
{
    return EVP_CIPHER_get_block_size(cipher);
}

inline int GetIVLengthWithinKeyBlock(const Cipher* cipher)
{
    if (EVP_CIPHER_get_mode(cipher) == EVP_CIPH_GCM_MODE)
        return EVP_GCM_TLS_FIXED_IV_LEN;
    else if (EVP_CIPHER_get_mode(cipher) == EVP_CIPH_CCM_MODE)
        return EVP_CCM_TLS_FIXED_IV_LEN;
    else
        return EVP_CIPHER_get_iv_length(cipher);
}

inline size_t GetIVLength(const CipherCtx* ctx)
{
    return EVP_CIPHER_CTX_get_iv_length(ctx);
}

inline size_t GetTagLength(const CipherCtx* ctx)
{
    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        return EVP_CCM_TLS_TAG_LEN;
    }
    return EVP_CIPHER_CTX_get_tag_length(ctx);
}

} // namespace snet::crypto