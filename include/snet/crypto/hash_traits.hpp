#pragma once
#include <cstdint>
#include <openssl/evp.h>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

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

    static inline size_t getSize(const Hash* hash) noexcept
    {
        return EVP_MD_size(hash);
    }

    static inline size_t getSize(const HashCtx* hashCtx) noexcept
    {
        return EVP_MD_CTX_size(hashCtx);
    }

    static inline const char* getName(const Hash* hash) noexcept
    {
        return EVP_MD_name(hash);
    }

    static inline HashCtxPtr createContext()
    {
        auto ctx = HashCtxPtr{EVP_MD_CTX_new()};
        ThrowIfTrue(ctx == nullptr, "bad alloc");
        return ctx;
    }

    static inline void resetContext(HashCtx* ctx) noexcept
    {
        EVP_MD_CTX_reset(ctx);
    }

    static inline void initHash(HashCtx* ctx, const Hash* algorithm)
    {
        ThrowIfFalse(0 < EVP_DigestInit(ctx, algorithm));
    }

    static inline void updateHash(HashCtx* ctx, nonstd::span<const uint8_t> message)
    {
        ThrowIfFalse(0 < EVP_DigestUpdate(ctx, message.data(), message.size()));
    }

    static inline void copyState(HashCtx* dst, const HashCtx* src)
    {
        ThrowIfFalse(0 < EVP_MD_CTX_copy_ex(dst, src));
    }

    static inline nonstd::span<uint8_t> finalHash(HashCtx* ctx, nonstd::span<uint8_t> buffer)
    {
        ThrowIfTrue(buffer.size() < static_cast<size_t>(EVP_MD_CTX_size(ctx)), "buffer too small");
        unsigned int digestSize = buffer.size();
        ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buffer.data(), &digestSize));
        return {buffer.data(), digestSize};
    }
};

} // namespace snet::crypto
