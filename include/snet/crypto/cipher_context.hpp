#pragma once
#include <openssl/evp.h>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

inline CipherCtxPtr CreateCipherCtx()
{
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    crypto::ThrowIfFalse(ctx);
    return ctx;
}

inline void ResetCipherCtx(CipherCtx* ctx) noexcept
{
    EVP_CIPHER_CTX_reset(ctx);
}

inline bool CipherIsAEAD(const Cipher* cipher)
{
    return EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
}

inline size_t GetKeyLength(const Cipher* cipher)
{
    return EVP_CIPHER_key_length(cipher);
}

inline size_t GetBlockLength(const Cipher* cipher)
{
    return EVP_CIPHER_block_size(cipher);
}

inline int GetIVLengthWithinKeyBlock(const Cipher* cipher)
{
    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
    {
        return EVP_GCM_TLS_FIXED_IV_LEN;
    }
    else if (EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE)
    {
        return EVP_CCM_TLS_FIXED_IV_LEN;
    }
    else
    {
        return EVP_CIPHER_iv_length(cipher);
    }
}

inline size_t GetIVLength(const CipherCtx* ctx)
{
    return EVP_CIPHER_CTX_iv_length(ctx);
}

inline size_t GetCipherMode(const CipherCtx* ctx)
{
    return EVP_CIPHER_CTX_mode(ctx);
}

inline size_t GetBlockLength(const CipherCtx* ctx)
{
    return EVP_CIPHER_CTX_block_size(ctx);
}

} // namespace snet::crypto