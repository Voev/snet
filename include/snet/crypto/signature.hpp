#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

size_t SignDigest(HashCtx* ctx, const Hash* hash, Key* privateKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<uint8_t> signature);

bool VerifyDigest(HashCtx* ctx, const Hash* hash, Key* publicKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<const uint8_t> signature);

class Signature
{
public:
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
};

} // namespace snet::crypto