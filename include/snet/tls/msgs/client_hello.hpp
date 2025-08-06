#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class ClientHello final
{
public:
    ClientHello() = default;

    ~ClientHello() noexcept = default;

    ClientHello(const ClientHello& other) = default;

    ClientHello& operator=(const ClientHello& other) = default;

    ClientHello(ClientHello&& other) noexcept = default;

    ClientHello& operator=(ClientHello&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

public:
    ProtocolVersion version;
    nonstd::span<const uint8_t> random;
    nonstd::span<const uint8_t> sessionID;
    nonstd::span<const uint16_t> suites;
    nonstd::span<const uint8_t> compMethods;
    nonstd::span<const uint8_t> extensions;
};

} // namespace snet::tls