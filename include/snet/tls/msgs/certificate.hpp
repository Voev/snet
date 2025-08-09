
#pragma once
#include <variant>
#include <snet/tls/msgs/tls1_certificate.hpp>
#include <snet/tls/msgs/tls13_certificate.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

class Session;

struct Certificate final
{
    std::variant<TLSv1Certificate, TLSv13Certificate> message;

    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static Certificate deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls
