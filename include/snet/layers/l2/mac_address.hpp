#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <array>
#include <casket/nonstd/span.hpp>

namespace snet::layers
{

struct MacAddress
{
    std::array<uint8_t, 6> bytes;

    MacAddress()
        : bytes{0}
    {
    }
    MacAddress(const uint8_t (&mac)[6])
    {
        std::copy(mac, mac + 6, bytes.begin());
    }
    MacAddress(std::initializer_list<uint8_t> list)
    {
        if (list.size() == 6)
            std::copy(list.begin(), list.end(), bytes.begin());
    }

    const uint8_t* data() const
    {
        return bytes.data();
    }
    uint8_t* data()
    {
        return bytes.data();
    }

    bool operator==(const MacAddress& other) const
    {
        return bytes == other.bytes;
    }
    bool operator!=(const MacAddress& other) const
    {
        return !(*this == other);
    }

    /// @brief Создаёт broadcast MAC.
    static MacAddress broadcast()
    {
        return MacAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    }

    /// @brief Создаёт нулевой MAC.
    static MacAddress zero()
    {
        return MacAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    }

    /// @brief Парсит MAC из строки "AA:BB:CC:DD:EE:FF".
    static MacAddress parse(const std::string& str)
    {
        MacAddress mac;
        unsigned int vals[6];
        if (std::sscanf(str.c_str(),
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        &vals[0],
                        &vals[1],
                        &vals[2],
                        &vals[3],
                        &vals[4],
                        &vals[5]) == 6)
        {
            for (int i = 0; i < 6; ++i)
                mac.bytes[i] = static_cast<uint8_t>(vals[i]);
        }
        return mac;
    }

    std::string toString() const
    {
        char buf[18];
        std::snprintf(buf,
                      sizeof(buf),
                      "%02x:%02x:%02x:%02x:%02x:%02x",
                      bytes[0],
                      bytes[1],
                      bytes[2],
                      bytes[3],
                      bytes[4],
                      bytes[5]);
        return std::string(buf);
    }
};

} // namespace snet::layers