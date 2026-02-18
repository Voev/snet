#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>

namespace snet::crypto
{

class Signature
{
public:
    static inline void signInit(HashCtx* ctx, const Hash* hash, Key* privateKey, KeyCtx** keyCtx = nullptr)
    {
        ThrowIfFalse(0 < EVP_DigestSignInit(ctx, keyCtx, hash, nullptr, privateKey));
    }

    static inline void signUpdate(HashCtx* ctx, nonstd::span<const uint8_t> message)
    {
        ThrowIfFalse(0 < EVP_DigestSignUpdate(ctx, message.data(), message.size()));
    }

    static inline nonstd::span<uint8_t> signFinal(HashCtx* ctx, nonstd::span<uint8_t> buffer)
    {
        size_t signatureSize = buffer.size();
        ThrowIfFalse(0 < EVP_DigestSignFinal(ctx, buffer.data(), &signatureSize));
        return {buffer.data(), signatureSize};
    }

    static inline nonstd::span<uint8_t> signMessage(HashCtx* ctx, const int keyAlgorithm, const Hash* algorithm,
                                                    Key* privateKey, nonstd::span<uint8_t> buffer,
                                                    nonstd::span<const uint8_t> tbs)
    {
        KeyCtx* keyCtx{nullptr};
        signInit(ctx, algorithm, privateKey, &keyCtx);

        if (keyAlgorithm == EVP_PKEY_RSA_PSS)
        {
            RsaAsymmKey::setPssSettings(keyCtx);
        }

        signUpdate(ctx, tbs);
        return signFinal(ctx, buffer);
    }

    static inline void verifyInit(HashCtx* ctx, const Hash* hash, Key* publicKey, KeyCtx** keyCtx = nullptr)
    {
        ThrowIfFalse(0 < EVP_DigestVerifyInit(ctx, keyCtx, hash, nullptr, publicKey));
    }

    static inline void verifyUpdate(HashCtx* ctx, nonstd::span<const uint8_t> message)
    {
        ThrowIfFalse(0 < EVP_DigestVerifyUpdate(ctx, message.data(), message.size()));
    }

    static inline void verifyFinal(HashCtx* ctx, nonstd::span<const uint8_t> signature)
    {
        ThrowIfFalse(0 < EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()));
    }

    static inline void verify(HashCtx* ctx, nonstd::span<const uint8_t> signature, nonstd::span<const uint8_t> tbs)
    {
        ThrowIfFalse(0 < EVP_DigestVerify(ctx, signature.data(), signature.size(), tbs.data(), tbs.size()));
    }

    static inline void verifyMessage(HashCtx* ctx, const int keyAlgorithm, const Hash* algorithm, Key* publicKey,
                                     nonstd::span<const uint8_t> signature, nonstd::span<const uint8_t> tbs)
    {
        KeyCtx* keyCtx{nullptr};
        verifyInit(ctx, algorithm, publicKey, &keyCtx);

        if (keyAlgorithm == EVP_PKEY_RSA_PSS)
        {
            RsaAsymmKey::setPssSettings(keyCtx);
        }

        verify(ctx, signature, tbs);
    }
};

} // namespace snet::crypto