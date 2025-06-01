#include <snet/tls/record_printer.hpp>
#include <snet/utils/print_hex.hpp>
#include <casket/utils/format.hpp>

using namespace casket::utils;

namespace snet::tls
{

RecordPrinter::RecordPrinter()
{
}

RecordPrinter::~RecordPrinter() noexcept
{
}

void RecordPrinter::handleRecord(const int8_t sideIndex, Session* session, Record* record)
{
    (void)session;

    const auto direction = (sideIndex == 0 ? "C->S" : "C<-S");
    std::cout << format("{}: {} {} [{}]", direction, record->version.toString(), toString(record->getType()),
                        record->getLength())
              << std::endl;

    if (record->isDecrypted())
    {
        auto data = record->getData();
        if (record->getType() == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(data[0]);
            std::cout << format("{} [{}] (decrypted)", toString(ht), data.size()) << std::endl;
        }
        utils::printHex(std::cout, data);
    }
    else
    {
        auto data = record->getData();
        if (record->getType() == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(data[TLS_HEADER_SIZE]);
            std::cout << format("{} [{}]", toString(ht), data.size() - TLS_HEADER_SIZE) << std::endl;
        }
        utils::printHex(std::cout, data.subspan(TLS_HEADER_SIZE));
    }
}

} // namespace snet::tls