/// @file
/// @brief Declaration of the RecordEncryptor class.

#pragma once
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/record_queue.hpp>

namespace snet::tls
{

/// @brief Class for encrypting TLS records.
class RecordEncryptor final : public IRecordHandler
{
public:
    /// @brief Default constructor.
    ///
    RecordEncryptor(RecordPool& recordPool)
        : recordPool_(recordPool)
    {}

    /// @brief Default destructor.
    ///
    ~RecordEncryptor() = default;

    /// @brief Handles a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] session Processed TLS session.
    /// @param[in] record Processed TLS record.
    ///
    void handleRecord(const int8_t sideIndex, Session* session, Record* record) override;

private:
    /// @brief Processes a ClientHello handshake message.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] session Processed TLS session.
    /// @param[in] record Processed TLS record.
    ///
    void processHandshakeClientHello(const int8_t sideIndex, Session* session, Record* record);

    void processHandshakeServerHello(const int8_t sideIndex, Session* session, Record* record);

private:
    RecordPool& recordPool_;
};

} // namespace snet::tls