#pragma once
#include <vector>
#include <iostream>
#include <iomanip>

namespace snet::utils
{

void compare_vectors(const std::vector<uint8_t>& vec1, const std::vector<uint8_t>& vec2)
{
    if (vec1.size() != vec2.size())
    {
        std::cout << "Vectors differ in size: " << vec1.size() << " vs " << vec2.size() << "\n";
    }

    size_t min_size = std::min(vec1.size(), vec2.size());
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
        std::cout << "Vectors are identical\n";
        return;
    }

    std::cout << "First difference at position: " << diff_pos << "\n\n";

    const size_t context_size = 5;
    size_t start = diff_pos > context_size ? diff_pos - context_size : 0;
    size_t end = std::min(diff_pos + context_size + 1, min_size);

    std::cout << "Position | Vector 1 | Vector 2\n";
    std::cout << "---------+----------+---------\n";

    for (size_t i = start; i < end; ++i)
    {
        std::cout << std::setw(7) << i << " | ";

        if (i < vec1.size())
        {
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(vec1[i]) << " | ";
        }
        else
        {
            std::cout << "     | ";
        }

        if (i < vec2.size())
        {
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(vec2[i]);
        }

        if (i == diff_pos)
        {
            std::cout << "  <<< DIFFERENCE";
        }

        std::cout << "\n";
    }
}

}