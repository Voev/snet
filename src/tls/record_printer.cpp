#include <snet/tls/record_printer.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/print_hex.hpp>

#include <casket/utils/format.hpp>

namespace snet::tls
{

RecordPrinter::RecordPrinter()
{
}

RecordPrinter::~RecordPrinter() noexcept
{
}

void RecordPrinter::handleRecord(const std::int8_t sideIndex, Session* session, Record* record)
{
    (void)session;

    const auto direction = (sideIndex == 0 ? "C->S" : "C<-S");
    std::cout << casket::format("{}: {} {} [{}]", direction, record->version.toString(), toString(record->getType()),
                                record->getLength())
              << std::endl;

    if (record->isDecrypted())
    {
        auto data = record->getDecryptedData();
        if (record->getType() == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(data[0]);
            std::cout << casket::format("{} [{}] (decrypted)", toString(ht), data.size()) << std::endl;
        }
        utils::printHex(std::cout, data, {}, true);
    }
    else
    {
        auto data = record->getData();
        if (record->getType() == RecordType::Handshake)
        {
            if (!session->getCipherState(sideIndex))
            {
                auto ht = static_cast<tls::HandshakeType>(data[TLS_HEADER_SIZE]);
                std::cout << casket::format("{} [{}]", toString(ht), data.size() - TLS_HEADER_SIZE) << std::endl;
            }
            else
            {
                std::cout << casket::format("{} [{}]", "Encrypted Handshake", data.size() - TLS_HEADER_SIZE)
                          << std::endl;
            }
        }
        utils::printHex(std::cout, data.subspan(TLS_HEADER_SIZE), {}, true);
    }
}

} // namespace snet::tls