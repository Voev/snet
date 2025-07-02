
#pragma once
#include <cstdint>
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct Certificate final
{
    Certificate() = default;

    ~Certificate() = default;

    void deserialize(const int8_t sideIndex, const ProtocolVersion& version, nonstd::span<const uint8_t> input);

    size_t serialize(const int8_t sideIndex, const ProtocolVersion& version, nonstd::span<uint8_t> output) const;

    std::vector<uint8_t> requestContext_;
    crypto::CertPtr cert_;
    crypto::CertStack1Ptr intermediateCerts_;
    std::vector<Extensions> certExts_;
};

} // namespace snet::tls
