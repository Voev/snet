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

void RecordPrinter::handleRecord(const std::int8_t sideIndex, const tls::Record& record)
{
    std::string label{};

    if (record.type() == tls::RecordType::Handshake)
    {
        auto ht = static_cast<tls::HandshakeType>(record.data()[0]);
        label = toString(ht);
    }

    const auto direction = (sideIndex == 0 ? "C->S" : "C<-S");

    std::cout << format("{}: {} {} [{}] {}", direction, record.version().toString(),
                        toString(record.type()), record.totalLength(), label)
              << std::endl;

    utils::printHex(std::cout, record.data());
}

} // namespace snet::tls