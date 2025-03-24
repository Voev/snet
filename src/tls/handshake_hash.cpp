#include <snet/tls/handshake_hash.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

namespace snet::tls
{

HandshakeHash::HandshakeHash() = default;

HandshakeHash::~HandshakeHash() noexcept = default;

void HandshakeHash::update(std::span<const uint8_t> in)
{
    std::copy(in.begin(), in.end(), std::back_inserter(messages_));
}

std::vector<uint8_t> HandshakeHash::final(std::string_view algorithm) const
{
    auto md = CipherSuiteManager::getInstance().fetchDigest(algorithm);
    crypto::ThrowIfFalse(md != nullptr);

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    crypto::ThrowIfFalse(ctx != nullptr);

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, messages_.data(), messages_.size()));

    unsigned int outlen(EVP_MD_get_size(md));
    std::vector<uint8_t> out(outlen);

    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, out.data(), &outlen));
    out.resize(outlen);

    return out;
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