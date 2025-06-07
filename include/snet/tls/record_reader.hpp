/// @file
/// @brief Declaration of the RecordReader class.

#pragma once
#include <vector>
#include <snet/tls/session.hpp>
#include <snet/tls/i_record_reader.hpp>

namespace snet::tls
{

/// @brief Class for reading TLS records.
class RecordReader final : public IRecordReader
{
public:
    /// @brief Default constructor.
    RecordReader();

    /// @brief Destructor.
    ~RecordReader() noexcept;

    /// @brief Copy constructor.
    /// @param other constant reference to the record reader.
    RecordReader(const RecordReader& other) = delete;

    /// @brief Copy assignment operator.
    /// @param other constant reference to the record reader.
    RecordReader& operator=(const RecordReader& other) = delete;

    /// @brief Move constructor.
    /// @param other rvalue reference to the record reader.
    RecordReader(RecordReader&& other) noexcept = default;

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the record reader.
    RecordReader& operator=(RecordReader&& other) noexcept = default;

    /// @brief Reads a TLS record from the input bytes.
    ///
    /// @param[in] sideIndex The index indicating the side (client or server).
    /// @param[in] inputBytes The input bytes to read from.
    /// @param[in] consumedBytes The number of bytes consumed during the read.
    ///
    /// @return The read TLS record.
    Record readRecord(const std::int8_t sideIndex, std::span<const std::uint8_t> inputBytes,
                      std::size_t& consumedBytes, Session* session) override;

private:
    std::vector<std::uint8_t> decryptedData_;
};

} // namespace snet::tls