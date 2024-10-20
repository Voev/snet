#pragma once
#include <vector>
#include <cstdint>

namespace snet::sniffer
{

using ClientRandom = std::vector<uint8_t>;

} // namespace snet::sniffer

namespace std
{

template <>
struct hash<snet::sniffer::ClientRandom>
{
    std::size_t
    operator()(const snet::sniffer::ClientRandom& random) const noexcept
    {
        std::size_t hash{0};
        for (auto byte : random)
        {
            hash = (hash << 5) - hash + byte;
        }
        return hash;
    }
};

} // namespace std