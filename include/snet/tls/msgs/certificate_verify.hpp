#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/signature_scheme.hpp>

namespace snet::tls
{

struct CertificateVerify final
{
    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    crypto::SignatureScheme scheme{0};
    nonstd::span<const uint8_t> signature;
};

} // namespace snet::tls