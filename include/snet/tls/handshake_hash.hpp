/// @file
/// @brief Declaration of the HandshakeHash class.

#pragma once
#include <casket/nonstd/span.hpp>
#include <vector>
#include <string_view>
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/hash_traits.hpp>

namespace snet::tls
{

/// @brief Class for handling handshake hash operations.
class HandshakeHash final
{
public:
    HandshakeHash() = default;

    ~HandshakeHash() noexcept = default;

    inline void commit(nonstd::span<const uint8_t> in)
    {
        std::copy(in.begin(), in.end(), std::back_inserter(messages_));
    }

    inline void init(HashCtx* context, const Hash* algorithm)
    {
        crypto::HashTraits::initHash(context, algorithm);
    }

    inline void update(HashCtx* context)
    {
        crypto::HashTraits::updateHash(context, messages_);
        messages_.clear();
    }

    inline void update(HashCtx* context, nonstd::span<const uint8_t> message)
    {
        crypto::HashTraits::updateHash(context, message);
    }

    inline nonstd::span<uint8_t> final(HashCtx* hashCtx)
    {
        return crypto::HashTraits::finalHash(hashCtx, digest_);
    }

    nonstd::span<uint8_t> final(HashCtx* hashCtx, const Hash* hashAlg)
    {
        crypto::HashTraits::initHash(hashCtx, hashAlg);
        crypto::HashTraits::updateHash(hashCtx, messages_);
        return crypto::HashTraits::finalHash(hashCtx, digest_);
    }

    void reset() noexcept
    {
        messages_.clear();
    }

private:
    std::vector<uint8_t> messages_;
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest_;
};

} // namespace snet::tls