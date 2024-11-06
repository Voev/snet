#pragma once
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <snet/utils/endianness.hpp>
#include <snet/utils/macros.hpp>

namespace snet::stream {

inline void read_data(const uint8_t* buffer, uint8_t* output_buffer, size_t size) {
    std::memcpy(output_buffer, buffer, size);
}

template <typename T>
void read_value(const uint8_t* buffer, T& value) {
    std::memcpy(&value, buffer, sizeof(value));
}

class MemoryReader {
public:
    MemoryReader(const uint8_t* buffer, size_t total_sz)
        : buffer_({buffer, total_sz}) {
    }

    MemoryReader(std::span<const uint8_t> data)
        : buffer_(data) {
    }

    template <typename T>
    T read() {
        T output;
        read(output);
        return output;
    }

    template <typename T>
    T read_le() {
        return utils::le_to_host(read<T>());
    }

    template <typename T>
    T read_be() {
        return utils::be_to_host(read<T>());
    }

    template <typename T>
    void read(T& value) {
        auto s = sizeof(value);
        if (!can_read(s)) {
            throw std::runtime_error("can't read value");
        }
        read_value(buffer_.data(), value);
        skip(sizeof(value));
    }

    void skip(size_t size) {
        if (SNET_UNLIKELY(size > buffer_.size_bytes())) {
            throw std::runtime_error("can't read value");
        }
        buffer_ = buffer_.subspan(size);
    }

    bool can_read(size_t byte_count) const {
        return SNET_LIKELY(buffer_.size_bytes() >= byte_count);
    }

    void read(uint8_t* output_buffer, size_t output_buffer_size) {
        if (!can_read(output_buffer_size)) {
            throw std::runtime_error("can't read value");
        }
        read_data(buffer_.data(), output_buffer, output_buffer_size);
        skip(output_buffer_size);
    }

    const uint8_t* pointer() const {
        return buffer_.data();
    }

    size_t size() const {
        return buffer_.size_bytes();
    }

private:
    std::span<const uint8_t> buffer_;
};

} // namespace snet::stream
