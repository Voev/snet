#pragma once
#include <casket/nonstd/span.hpp>
#include <cassert>
#include <cstdint>

namespace snet::utils
{

class MemoryViewer final
{
public:
    MemoryViewer(const uint8_t* data, size_t size)
        : data_({data, size}) {
    }

    MemoryViewer(nonstd::span<const uint8_t> data)
        : data_(data)
    {}

    ~MemoryViewer() noexcept = default;

    nonstd::span<const uint8_t> view(size_t size)
    {
        assert(data_.size() >= size);
        auto subspan = data_.subspan(0, size);
        data_ = data_.subspan(size);
        return subspan;
    }

private:
    nonstd::span<const uint8_t> data_;
};

} // namespace snet::utils