#pragma once
#include <openssl/evp.h>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

class CipherTraits final
{
public:
    static inline CipherCtxPtr createContext()
    {
        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        crypto::ThrowIfFalse(ctx);
        return ctx;
    }

    static inline void resetContext(CipherCtx* ctx) noexcept
    {
        EVP_CIPHER_CTX_reset(ctx);
    }

    static inline bool isAEAD(const Cipher* cipher)
    {
        return EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
    }

    static inline size_t getKeyLength(const Cipher* cipher)
    {
        return EVP_CIPHER_key_length(cipher);
    }

    static inline size_t getBlockLength(const Cipher* cipher)
    {
        return EVP_CIPHER_block_size(cipher);
    }

    static inline int getIVLengthWithinKeyBlock(const Cipher* cipher)
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

    static inline size_t getIVLength(const CipherCtx* ctx)
    {
        return EVP_CIPHER_CTX_iv_length(ctx);
    }

    static inline size_t getMode(const CipherCtx* ctx)
    {
        return EVP_CIPHER_CTX_mode(ctx);
    }

    static inline size_t getBlockLength(const CipherCtx* ctx)
    {
        return EVP_CIPHER_CTX_block_size(ctx);
    }
};

} // namespace snet::crypto