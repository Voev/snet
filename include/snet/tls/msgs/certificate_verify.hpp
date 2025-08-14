#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/signature_scheme.hpp>

namespace snet::tls
{

class Session;

struct CertificateVerify final
{
    void parse(nonstd::span<const uint8_t> input);

    static CertificateVerify deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;

    crypto::SignatureScheme scheme{0};
    nonstd::span<const uint8_t> signature;
};

} // namespace snet::tls