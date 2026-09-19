#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <snet/io.hpp>

namespace snet::driver
{

struct AFPacketConfig
{
    std::vector<std::string> devices;
    uint32_t bufferSizeMb{128};
    int32_t snapLen{0};
    int32_t timeoutMs{-1};
    bool debug{false};
    bool useTxRing{false};

    struct Fanout
    {
        bool enabled{false};
        uint16_t type{0};
        uint16_t flags{0};
    } fanout;

    std::string filter;

    bool parse(const snet::io::Config& cfg);
};

} // namespace snet::driver