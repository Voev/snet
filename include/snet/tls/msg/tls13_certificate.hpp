#pragma once
#include <cstdint>
#include <vector>
#include <span>
#include <snet/tls/extensions.hpp>

namespace snet::tls::msg
{

struct TLSv13Certificate final
{
    TLSv13Certificate() = default;

    ~TLSv13Certificate() = default;

    void deserialize(std::span<const uint8_t> message);

    size_t serialize(std::span<uint8_t> buffer) const;

    std::vector<uint8_t> requestContext;
    std::vector<std::vector<uint8_t>> certs;
    std::vector<Extensions> certExts;
};

}