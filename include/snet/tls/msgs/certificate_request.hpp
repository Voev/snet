
#pragma once

#include <casket/nonstd/variant.hpp>
#include <snet/tls/msgs/tls1_certificate_request.hpp>
#include <snet/tls/msgs/tls12_certificate_request.hpp>
#include <snet/tls/msgs/tls13_certificate_request.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

class Session;

struct CertificateRequest final
{
    nonstd::variant<TLSv1CertificateRequest, TLSv12CertificateRequest, TLSv13CertificateRequest> message;

    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static CertificateRequest deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls
