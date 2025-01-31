#pragma once
#include <string>
#include <string_view>
#include <span>
#include <vector>
#include <iostream>
#include <iomanip>

namespace snet::utils
{

inline void printHex(std::string_view message, std::span<const uint8_t> data)
{
    std::cout << message << "(" << std::dec << data.size() << ")" << std::endl;
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";

        if ((i + 1) % 16 == 0)
        {
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
}

inline void printHex(std::span<const uint8_t> data)
{
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";

        if ((i + 1) % 16 == 0)
        {
            std::cout << "|";
            for (std::size_t j = i - 15; j <= i; ++j)
            {
                auto ch = static_cast<char>(data[j]);
                if (isprint(ch))
                { 
                    std::cout << ch;
                }
                else
                {
                    std::cout << '.';
                }
            }
            std::cout << std::endl;
        }
    }

    std::cout << std::dec;

    int remaining = data.size() % 16;
    if (remaining != 0)
    {
        for (int i = 0; i < 16 - remaining; ++i)
        {
            std::cout << "   ";
        }

        std::cout << "|";
        for (std::size_t i = data.size() - remaining; i < data.size(); ++i)
        {
            auto ch = static_cast<char>(data[i]);
            if (isprint(ch))
            {
                std::cout << ch;
            }
            else
            { 
                std::cout << '.';
            }
        }
        std::cout << std::endl;
    }
}

} // namespace snet::utils