#pragma once
#include <span>
#include <cstdint>
#include <snet/tls/record.hpp>

namespace snet::tls
{

class IRecordReader
{
public:
    IRecordReader() = default;

    virtual ~IRecordReader() = default;

    virtual Record readRecord(const std::int8_t sideIndex, std::span<const std::uint8_t> inputBytes,
                              std::size_t& consumedBytes) = 0;
};

} // namespace snet::tls