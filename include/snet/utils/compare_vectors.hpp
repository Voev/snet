#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

namespace snet::utils
{

inline std::string CompareVectors(const std::vector<uint8_t>& vec1,
                                   const std::vector<uint8_t>& vec2)
{
    std::ostringstream out;

    if (vec1.size() != vec2.size())
    {
        out << "Vectors differ in size: " << vec1.size() << " vs " << vec2.size() << "\n";
    }

    const size_t min_size = std::min(vec1.size(), vec2.size());
    size_t diff_pos = min_size;

    for (size_t i = 0; i < min_size; ++i)
    {
        if (vec1[i] != vec2[i])
        {
            diff_pos = i;
            break;
        }
    }

    if (diff_pos == min_size && vec1.size() == vec2.size())
    {
        out << "Vectors are identical\n";
        return out.str();
    }

    out << "First difference at position: " << diff_pos << "\n\n";

    const size_t context_size = 5;
    const size_t start = diff_pos > context_size ? diff_pos - context_size : 0;
    const size_t end   = std::min(diff_pos + context_size + 1, min_size);

    out << "Position | Vector 1 | Vector 2\n";
    out << "---------+----------+---------\n";

    for (size_t i = start; i < end; ++i)
    {
        out << std::setw(7) << i << " | ";

        if (i < vec1.size())
            out << "0x" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(vec1[i]) << std::dec << " | ";
        else
            out << "     | ";

        if (i < vec2.size())
            out << "0x" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(vec2[i]) << std::dec;
        else
            out << "     ";

        if (i == diff_pos)
            out << "  <<< DIFFERENCE";

        out << "\n";
    }

    if (vec1.size() != vec2.size())
    {
        const auto& longer = vec1.size() > vec2.size() ? vec1 : vec2;
        const size_t tail_start = min_size;
        const size_t tail_end   = std::min(min_size + context_size + 1, longer.size());

        if (tail_start < tail_end)
        {
            out << "\nExtra bytes in "
                << (vec1.size() > vec2.size() ? "vector 1" : "vector 2")
                << ":\n";
            for (size_t i = tail_start; i < tail_end; ++i)
            {
                out << std::setw(7) << i << " | 0x"
                    << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(longer[i]) << std::dec << "\n";
            }
        }
    }

    return out.str();
}

} // namespace snet::utils