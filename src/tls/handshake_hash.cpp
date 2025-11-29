#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/hash_traits.hpp>

#include <snet/tls/handshake_hash.hpp>

using namespace snet::crypto;

namespace snet::tls
{

HandshakeHash::HandshakeHash() = default;

HandshakeHash::~HandshakeHash() noexcept = default;

void HandshakeHash::update(nonstd::span<const uint8_t> in)
{
    std::copy(in.begin(), in.end(), std::back_inserter(messages_));
}

nonstd::span<uint8_t> HandshakeHash::final(HashCtx* hashCtx, const Hash* hashAlg, nonstd::span<uint8_t> buffer) const
{
    HashTraits::initHash(hashCtx, hashAlg);
    HashTraits::updateHash(hashCtx, messages_);
    return HashTraits::finalHash(hashCtx, buffer);
}

const std::vector<uint8_t>& HandshakeHash::getContents() const
{
    return messages_;
}

void HandshakeHash::reset()
{
    messages_.clear();
}

} // namespace snet::tls