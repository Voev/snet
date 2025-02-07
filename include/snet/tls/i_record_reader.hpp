/// @file
/// @brief Declaration of the IRecordReader interface.

#pragma once
#include <span>
#include <cstdint>
#include <snet/tls/record.hpp>

namespace snet::tls
{

/// @brief Interface for reading TLS records.
class IRecordReader
{
public:
    /// @brief Default constructor.
    IRecordReader() = default;

    /// @brief Virtual destructor.
    virtual ~IRecordReader() = default;

    /// @brief Reads a TLS record from the input bytes.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param inputBytes The input bytes to read from.
    /// @param consumedBytes The number of bytes consumed during the read.
    /// @return The read TLS record.
    virtual Record readRecord(const std::int8_t sideIndex, std::span<const std::uint8_t> inputBytes,
                              std::size_t& consumedBytes) = 0;
};

} // namespace snet::tls