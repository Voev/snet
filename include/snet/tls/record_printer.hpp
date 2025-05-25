/// @file
/// @brief Declaration of the RecordPrinter class.

#pragma once
#include <snet/tls/i_record_handler.hpp>

namespace snet::tls
{

/// @brief Class for printing TLS records.
class RecordPrinter final : public IRecordHandler
{
public:
    /// @brief Default constructor.
    RecordPrinter();

    /// @brief Destructor.
    ~RecordPrinter() noexcept;

    /// @brief Handles a TLS record by printing its details.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to handle.
    /// @param record The TLS record to handle.
    void handleRecord(const int8_t sideIndex, Session* session, Record* record) override;
};

} // namespace snet::tls