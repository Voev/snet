#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <casket/utils/noncopyable.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct ServerHello final : public casket::NonCopyable
{
    ServerHello() = default;

    ~ServerHello() noexcept = default;

    ServerHello(ServerHello&& other) noexcept = default;

    ServerHello& operator=(ServerHello&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> message);

    size_t serialize(nonstd::span<uint8_t> buffer) const;

    ProtocolVersion legacyVersion;
    std::vector<uint8_t> random;
    std::vector<uint8_t> sessionID;
    uint16_t cipherSuite;
    uint8_t compMethod;
    Extensions extensions;
    bool isHelloRetryRequest;
};

} // namespace snet::tls