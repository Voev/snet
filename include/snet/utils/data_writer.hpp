#pragma once
#include <span>
#include <stdexcept>
#include <cstdint>
#include <snet/utils/load_store.hpp>


namespace snet::utils
{
template <typename T>
size_t append_tls_length_value(std::span<uint8_t> output_buf, const T* vals, size_t vals_size, size_t tag_size)
{
    const size_t T_size = sizeof(T);
    const size_t val_bytes = T_size * vals_size;
    const size_t required_size = tag_size + val_bytes;

    if (output_buf.size() < required_size)
    {
        throw std::runtime_error("append_tls_length_value: buffer too small");
    }

    if (tag_size != 1 && tag_size != 2 && tag_size != 3)
    {
        throw std::runtime_error("append_tls_length_value: invalid tag size");
    }

    if ((tag_size == 1 && val_bytes > 255) || (tag_size == 2 && val_bytes > 65535) ||
        (tag_size == 3 && val_bytes > 16777215))
    {
        throw std::runtime_error("append_tls_length_value: value too large");
    }

    for (size_t i = 0; i != tag_size; ++i)
    {
        output_buf[i] = get_byte_var(sizeof(val_bytes) - tag_size + i, val_bytes);
    }

    for (size_t i = 0; i != vals_size; ++i)
    {
        for (size_t j = 0; j != T_size; ++j)
        {
            output_buf[tag_size + i * T_size + j] = get_byte_var(j, vals[i]);
        }
    }

    return required_size;
}
} // namespace snet::utils