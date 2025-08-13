#pragma once
#include <array>
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

struct TLSv1Certificate final
{
    static constexpr size_t kMaxCertChain{10};
    struct Entry final
    {
        nonstd::span<const uint8_t> certData;
        Cert* cert{nullptr};
    };

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    std::array<Entry, kMaxCertChain> entryList;
    uint8_t entryCount{0};
};

} // namespace snet::tls