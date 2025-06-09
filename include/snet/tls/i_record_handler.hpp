/// @file
/// @brief Declaration of the record handling interface.

#pragma once
#include <snet/tls/record.hpp>
#include <snet/tls/session.hpp>

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
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] session TLS session.
    /// @param[in] record TLS record.
    ///
    virtual void handleRecord(const std::int8_t sideIndex, Session* session, Record* record) = 0;
};

} // namespace snet::tls