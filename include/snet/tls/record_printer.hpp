/// @file
/// @brief Declaration of the RecordPrinter class.

#pragma once
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/session.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

inline void PrintRecord(const std::int8_t sideIndex, const Session* session, Record* record)
{
    const auto direction = (sideIndex == 0 ? "C->S" : "C<-S");
    std::cout << casket::format("{}: {} {} [{}]", direction, record->getVersion().toString(), toString(record->getType()),
                                record->getLength())
              << std::endl;

    if (record->isPlaintext())
    {
        auto data = record->getPlaintext();
        if (record->getType() == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(data[0]);
            std::cout << casket::format("{} [{}] (decrypted)", toString(ht), data.size()) << std::endl;
        }
        utils::printHex(std::cout, data, {}, true);
    }
    else
    {
        auto data = record->getCiphertext();
        if (record->getType() == RecordType::Handshake)
        {
            if (!session->getCipherState(sideIndex))
            {
                auto ht = static_cast<tls::HandshakeType>(data[0]);
                std::cout << casket::format("{} [{}]", toString(ht), data.size()) << std::endl;
            }
            else
            {
                std::cout << casket::format("{} [{}]", "Encrypted Handshake", data.size())
                          << std::endl;
            }
        }
        utils::printHex(std::cout, data, {}, true);
    }
}

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