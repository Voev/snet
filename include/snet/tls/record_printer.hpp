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

    /// @brief Handles a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] session TLS session.
    /// @param[in] record TLS record.
    ///
    void handleRecord(const std::int8_t sideIndex, Session* session, Record* record) override;
};

} // namespace snet::tls