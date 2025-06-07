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

void RecordPrinter::handleRecord(const std::int8_t sideIndex, Session* session, Record* record)
{
    (void)session;

    std::cout << format("{}: {} {} [{}]", (sideIndex == 0 ? "C->S" : "C<-S"), record->version().toString(),
                        toString(record->type()), record->totalLength())
              << std::endl;

    auto data = record->data();
    if (record->type() == RecordType::Handshake)
    {
        auto ht = static_cast<tls::HandshakeType>(data[TLS_HEADER_SIZE]);
        std::cout << format("{} [{}]", toString(ht), data.size() - TLS_HEADER_SIZE) << std::endl;
    }

    utils::printHex(std::cout, data.subspan(TLS_HEADER_SIZE));
}

} // namespace snet::tls