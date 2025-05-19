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

inline size_t GetBlockLength(const Cipher* cipher)
{
    return EVP_CIPHER_get_block_size(cipher);
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

}