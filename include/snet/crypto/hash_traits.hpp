#pragma once
#include <cstdint>
#include <openssl/evp.h>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

inline HashCtxPtr CreateHashCtx()
{
    auto ctx = HashCtxPtr{EVP_MD_CTX_new()};
    ThrowIfTrue(ctx == nullptr, "bad alloc");
    return ctx;
}

inline void ResetHashCtx(HashCtx* ctx) noexcept
{
    EVP_MD_CTX_reset(ctx);
}

inline void InitHash(HashCtx* ctx, const Hash* algorithm)
{
    ThrowIfFalse(0 < EVP_DigestInit(ctx, algorithm));
}

inline void UpdateHash(HashCtx* ctx, nonstd::span<const uint8_t> message)
{
    ThrowIfFalse(0 < EVP_DigestUpdate(ctx, message.data(), message.size()));
}

inline nonstd::span<uint8_t> FinalHash(HashCtx* ctx, nonstd::span<uint8_t> buffer)
{
    ThrowIfTrue(buffer.size() < static_cast<size_t>(EVP_MD_CTX_size(ctx)), "buffer too small");
    unsigned int digestSize = buffer.size();
    ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buffer.data(), &digestSize));
    return {buffer.data(), digestSize};
}

inline size_t GetHashSize(const Hash* hash) noexcept
{
    return EVP_MD_size(hash);
}

inline size_t GetHashSize(const HashCtx* hashCtx) noexcept
{
    return EVP_MD_CTX_size(hashCtx);
}

inline const char* GetHashName(const Hash* hash) noexcept
{
    return EVP_MD_name(hash);
}

class HashTraits
{
public:
    static inline bool isAlgorithm(const Hash* hash, std::string_view alg)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        return EVP_MD_is_a(hash, alg.data());
#else
        return (EVP_MD_nid(hash) == OBJ_sn2nid(alg.data()));
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    }
};

} // namespace snet::crypto
