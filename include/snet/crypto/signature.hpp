#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/crypto/exception.hpp>

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
};

} // namespace snet::crypto