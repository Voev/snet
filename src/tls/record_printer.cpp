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
    std::cout << format("{}: {} {} [{}]", direction, record->version.toString(), toString(record->type), record->length)
              << std::endl;

    if (record->is_decrypted)
    {
        if (record->type == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(record->decrypted[0]);
            std::cout << format("{} [{}] (decrypted)", toString(ht), record->decryptedLength) << std::endl;
        }
        utils::printHex(std::cout, {record->decrypted, record->decryptedLength});
    }
    else
    {
        if (record->type == RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(record->data[TLS_HEADER_SIZE]);
            std::cout << format("{} [{}]", toString(ht), record->length - TLS_HEADER_SIZE) << std::endl;
        }
        utils::printHex(std::cout, {record->data + TLS_HEADER_SIZE, record->length - TLS_HEADER_SIZE});
    }
}

} // namespace snet::tls