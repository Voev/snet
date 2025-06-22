#pragma once
#include <string>
#include <string_view>
#include <span>
#include <vector>
#include <iostream>
#include <iomanip>

namespace snet::utils
{

inline void printHex(std::ostream& os, std::span<const uint8_t> data, std::string_view message = {},
                     bool printable = false)
{
    if (!message.empty())
        os << message << "(" << std::dec << data.size() << ")" << std::endl;

    for (std::size_t i = 0; i < data.size(); ++i)
    {
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";

        if ((i + 1) % 16 == 0)
        {
            if (printable)
            {
                os << "|";
                for (std::size_t j = i - 15; j <= i; ++j)
                {
                    auto ch = static_cast<char>(data[j]);
                    if (isprint(ch))
                    {
                        os << ch;
                    }
                    else
                    {
                        os << '.';
                    }
                }
            }
            os << std::endl;
        }
    }

    os << std::dec;

    int remaining = data.size() % 16;
    if (remaining != 0)
    {
        for (int i = 0; i < 16 - remaining; ++i)
        {
            os << "   ";
        }

        if (printable)
        {
            os << "|";
            for (std::size_t i = data.size() - remaining; i < data.size(); ++i)
            {
                auto ch = static_cast<char>(data[i]);
                if (isprint(ch))
                {
                    os << ch;
                }
                else
                {
                    os << '.';
                }
            }
        }
        os << std::endl;
    }
}

} // namespace snet::utils