#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class ServerHello final
{
public:
    ServerHello() = default;

    ~ServerHello() noexcept = default;

    ServerHello(const ServerHello& other) = default;

    ServerHello& operator=(const ServerHello& other) = default;

    ServerHello(ServerHello&& other) noexcept = default;

    ServerHello& operator=(ServerHello&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

public:
    ProtocolVersion version;
    nonstd::span<const uint8_t> random;
    nonstd::span<const uint8_t> sessionID;
    uint16_t cipherSuite{0};
    uint8_t compMethod{0};
    nonstd::span<const uint8_t> extensions;
    bool isHelloRetryRequest{false};
};

} // namespace snet::tls