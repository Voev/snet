/// @file
/// @brief Declaration of the record handling interface.

#pragma once
#include <snet/tls/record.hpp>
#include <snet/tls/msgs/client_hello.hpp>

namespace snet::tls
{

class Session;

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
    virtual void handleRecord(const std::int8_t sideIndex, Session* session, Record* record)
    {
        (void)sideIndex;
        (void)session;
        (void)record;
    }

    virtual void handleClientHello(const ClientHello& clientHello, Session* session)
    {
        (void)clientHello;
        (void)session;
    }
};

} // namespace snet::tls