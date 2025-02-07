/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <snet/tls/version.hpp>
#include <snet/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS record.
class Record final
{
public:
    /// @brief Constructor with record type, protocol version, and data.
    /// @param type The record type.
    /// @param version The protocol version.
    /// @param data The record data.
    explicit Record(RecordType type, ProtocolVersion version, std::span<const uint8_t> data)
        : type_(type)
        , version_(version)
        , data_(data)
    {
    }

    /// @brief Gets the record type.
    /// @return The record type.
    RecordType type() const
    {
        return type_;
    }

    /// @brief Gets the protocol version.
    /// @return The protocol version.
    ProtocolVersion version() const
    {
        return version_;
    }

    /// @brief Gets the record data.
    /// @return The record data.
    std::span<const uint8_t> data() const
    {
        return data_;
    }

    /// @brief Gets the total length of the record.
    /// @return The total length of the record.
    size_t totalLength() const
    {
        return TLS_HEADER_SIZE + data_.size_bytes();
    }

private:
    RecordType type_;
    ProtocolVersion version_;
    std::span<const uint8_t> data_;
};

} // namespace snet::tls