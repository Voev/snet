#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Session;

struct ServerHello final
{
    ProtocolVersion version;
    nonstd::span<const uint8_t> random;
    nonstd::span<const uint8_t> sessionID;
    uint16_t cipherSuite{0};
    uint8_t compMethod{0};
    nonstd::span<const uint8_t> extensions;
    bool isHelloRetryRequest{false};

    void parse(nonstd::span<const uint8_t> input);

    static ServerHello deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls