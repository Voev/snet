#pragma once
#include <cstdint>
#include <vector>
#include <span>

namespace snet::tls::msg
{

struct CertEntry
{
    std::vector<uint8_t> certificate;
};

struct Certificate final
{
    Certificate() = default;

    ~Certificate() = default;

    void deserialize(std::span<const uint8_t> message);

    size_t serialize(std::span<uint8_t> buffer) const;

    std::vector<CertEntry> certEntries;
};

}