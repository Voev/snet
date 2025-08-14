#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Session;

struct ClientHello final
{
    ProtocolVersion version;
    nonstd::span<const uint8_t> random;
    nonstd::span<const uint8_t> sessionID;
    nonstd::span<const uint8_t> suites; ///< Ciphersuite codes (interpreted as a pair of bytes in BE)
    nonstd::span<const uint8_t> compMethods;
    nonstd::span<const uint8_t> extensions;

    void parse(nonstd::span<const uint8_t> input);

    static ClientHello deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls