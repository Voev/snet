#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <casket/utils/noncopyable.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/signature_scheme.hpp>

#include <snet/crypto/group_params.hpp>

namespace snet::tls
{

class ServerKeyExchange final : public casket::NonCopyable
{
public:
    ServerKeyExchange() = default;

    ~ServerKeyExchange() noexcept = default;

    ServerKeyExchange(ServerKeyExchange&& other) noexcept = default;

    ServerKeyExchange& operator=(ServerKeyExchange&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> input, const std::string& kex, const std::string& auth,
                     const ProtocolVersion& version);

    size_t serialize(nonstd::span<uint8_t> buffer) const;

    const std::vector<uint8_t>& getParams() const noexcept;

private:
    crypto::KeyPtr serverPublicKey_;
    std::vector<uint8_t> params_;
    std::vector<uint8_t> signature_;
    SignatureScheme scheme_;
};

} // namespace snet::tls