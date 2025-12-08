#pragma once
#include <array>
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

struct TLSv12CertificateRequest final
{
    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> certTypes;
    nonstd::span<const uint8_t> supportedSigAlgs;
    nonstd::span<const uint8_t> certAuthorities;
};

} // namespace snet::tls