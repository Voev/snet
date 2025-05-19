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

void RecordPrinter::handleRecord(const std::int8_t sideIndex, tls::Record& record)
{
    (void)sideIndex;

    std::string label = toString(record.type);
    if (record.type == RecordType::Handshake)
    {
        auto ht = static_cast<tls::HandshakeType>(record.data[TLS_HEADER_SIZE]);
        label = toString(ht);
    }

    if (record.is_decrypted)
    {
        std::cout << format("{} [{}] (decrypted)", label, record.decryptedLength) << std::endl;
        utils::printHex(std::cout, {record.decrypted, record.decryptedLength});
    }
    else
    {
        std::cout << format("{} [{}]", label, record.length - TLS_HEADER_SIZE) << std::endl;
        utils::printHex(std::cout, {record.data + TLS_HEADER_SIZE, record.length - TLS_HEADER_SIZE});
    }
}

} // namespace snet::tls