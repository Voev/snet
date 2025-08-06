#pragma once
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

struct EncryptedExtensions final
{
    void deserialize(nonstd::span<const uint8_t> input)
    {
        extensions = input;
    }

    //size_t serialize(nonstd::span<uint8_t> buffer) const;

    nonstd::span<const uint8_t> extensions;
};

} // namespace snet::tls