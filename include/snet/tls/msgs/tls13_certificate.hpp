#pragma once
#include <array>
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct TLSv13Certificate final
{
    static constexpr size_t kMaxCertChain{10};
    struct Entry final
    {
        nonstd::span<const uint8_t> certData;
        nonstd::span<const uint8_t> extsData;
        X509Cert* cert{nullptr};
        Extensions* extensions{nullptr};
    };

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> requestContext;
    std::array<Entry, kMaxCertChain> entryList;
    uint8_t entryCount{0};
};

} // namespace snet::tls