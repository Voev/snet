#pragma once
#include <snet/cpp_port/span.hpp>
#include <vector>
#include <iostream>
#include <snet/tls/version.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

struct ClientHello final : public utils::NonCopyable
{
    ClientHello() = default;

    ~ClientHello() noexcept = default;

    ClientHello(ClientHello&& other) noexcept = default;

    ClientHello& operator=(ClientHello&& other) noexcept = default;

    void deserialize(cpp::span<const uint8_t> message);

    size_t serialize(cpp::span<uint8_t> buffer) const;

    void print(std::ostream& os) const;

    ProtocolVersion legacyVersion;
    std::vector<uint8_t> random;
    std::vector<uint8_t> sessionID;
    std::vector<uint16_t> suites;
    std::vector<uint8_t> compMethods;
    Extensions extensions;
};

} // namespace snet::tls