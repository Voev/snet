#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/hash_traits.hpp>

#include <snet/tls/handshake_hash.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

HandshakeHash::HandshakeHash() = default;

HandshakeHash::~HandshakeHash() noexcept = default;

void HandshakeHash::update(nonstd::span<const uint8_t> in)
{
    //utils::printHex(std::cout, in, "TranscriptHash", true);
    std::copy(in.begin(), in.end(), std::back_inserter(messages_));
}

nonstd::span<uint8_t> HandshakeHash::final(HashCtx* hashCtx, const Hash* hashAlg, nonstd::span<uint8_t> buffer) const
{
    crypto::InitHash(hashCtx, hashAlg);
    crypto::UpdateHash(hashCtx, messages_);
    return crypto::FinalHash(hashCtx, buffer);
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