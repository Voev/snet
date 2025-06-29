#pragma once
#include <vector>
#include <iostream>
#include <snet/tls/version.hpp>
#include <snet/tls/extensions.hpp>
#include <casket/nonstd/span.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::tls
{

struct ClientHello final : public casket::NonCopyable
{
    ClientHello() = default;

    ~ClientHello() noexcept = default;

    ClientHello(ClientHello&& other) noexcept = default;

    ClientHello& operator=(ClientHello&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> message);

    size_t serialize(nonstd::span<uint8_t> buffer) const;

    void print(std::ostream& os) const;

    ProtocolVersion legacyVersion;
    std::vector<uint8_t> random;
    std::vector<uint8_t> sessionID;
    std::vector<uint16_t> suites;
    std::vector<uint8_t> compMethods;
    Extensions extensions;
};

} // namespace snet::tls