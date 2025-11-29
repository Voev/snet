#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/hash_traits.hpp>

namespace snet::tls
{

class HandshakeHash final
{
public:
    HandshakeHash()
        : context_(crypto::HashTraits::createContext())
    {
    }

    ~HandshakeHash() noexcept
    {
    }

    inline void commit(nonstd::span<const uint8_t> in)
    {
        std::copy(in.begin(), in.end(), std::back_inserter(messages_));
    }

    inline void init(const Hash* algorithm)
    {
        crypto::HashTraits::initHash(context_, algorithm);
    }

    inline void update()
    {
        crypto::HashTraits::updateHash(context_, messages_);
        messages_.clear();
    }

    inline void update(nonstd::span<const uint8_t> message)
    {
        crypto::HashTraits::updateHash(context_, message);
    }

    inline nonstd::span<uint8_t> final(HashCtx* transitContext)
    {
        crypto::HashTraits::copyState(transitContext, context_);
        return crypto::HashTraits::finalHash(transitContext, digest_);
    }

    void reset() noexcept
    {
        messages_.clear();
        crypto::HashTraits::resetContext(context_);
    }

private:
    std::vector<uint8_t> messages_;
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest_;
    crypto::HashCtxPtr context_;
};

} // namespace snet::tls