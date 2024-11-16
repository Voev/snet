#include <iostream>
#include <iomanip>

#include <snet/utils/hexlify.hpp>
#include <snet/utils/exception.hpp>

namespace snet::utils
{

inline uint8_t char2digit(const char ch)
{
    switch (ch)
    {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'a':
    case 'A':
        return 0x0A;
    case 'b':
    case 'B':
        return 0x0B;
    case 'c':
    case 'C':
        return 0x0C;
    case 'd':
    case 'D':
        return 0x0D;
    case 'e':
    case 'E':
        return 0x0E;
    case 'f':
    case 'F':
        return 0x0F;
    default:
        throw RuntimeError("invalid hexadecimal symbol");
    }
};

std::string hexlify(std::span<const uint8_t> in)
{
    static const uint8_t kHexMap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string out;
    out.resize(in.size() * 2);

    for (size_t i = 0, j = 0; i < in.size() && j < out.size(); ++i)
    {
        out[j++] = kHexMap[(in[i] >> 4)];
        if (j < out.size())
        {
            out[j++] = kHexMap[in[i] & 0xF];
        }
    }

    return out;
}

std::vector<uint8_t> unhexlify(std::string_view in)
{

    ThrowIfFalse(in.size() % 2 == 0, "even string length required");

    std::vector<uint8_t> out;
    out.resize(in.size() / 2);

    for (size_t i = 0, j = 0; i < in.size() && j < out.size(); i += 2)
    {
        out[j++] = char2digit(in[i]) << 4 | char2digit(in[i + 1]);
    }

    return out;
}

void printHex(std::string_view message, std::span<const uint8_t> data)
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

void printHex(std::span<const uint8_t> data)
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