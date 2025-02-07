/// @file
/// @brief Declaration of the IRecordHandler interface.

#pragma once
#include <snet/tls/record.hpp>

namespace snet::tls
{

/// @brief Interface for handling TLS records.
class IRecordHandler
{
public:
    /// @brief Default constructor.
    IRecordHandler() = default;

    /// @brief Virtual destructor.
    virtual ~IRecordHandler() = default;

    /// @brief Handles a TLS record.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param record The TLS record to handle.
    virtual void handleRecord(const std::int8_t sideIndex, const Record& record) = 0;
};

} // namespace snet::tls