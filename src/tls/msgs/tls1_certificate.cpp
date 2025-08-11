#include <snet/tls/msgs/tls1_certificate.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv1Certificate::deserialize(nonstd::span<const uint8_t> buffer)
{
    utils::DataReader reader("Certificate", buffer);

    const size_t certEntriesLength = reader.get_uint24_t();
    ThrowIfTrue(reader.remaining_bytes() != certEntriesLength, "Certificate: message malformed");

    while (reader.has_remaining())
    {
        Entry entry;
        entry.data = reader.get_span_length_and_value(3);
        certList[certCount++] = std::move(entry);
    }

    reader.assert_done();
}

size_t TLSv1Certificate::serialize(nonstd::span<uint8_t> output) const
{
    size_t totalLength{0};

    auto header = output;
    auto entries = header.subspan(3);
    totalLength += 3;

    uint32_t certSize;
    uint32_t entriesLength{0};
    for (size_t i = 0; i < certCount; ++i)
    {
        auto certData = entries.subspan(3);
        uint8_t* ptr = certData.data();

        certSize = i2d_X509(certList[i].cert, &ptr);

        entries[0] = casket::get_byte<1>(certSize);
        entries[1] = casket::get_byte<2>(certSize);
        entries[2] = casket::get_byte<3>(certSize);
        
        entries = entries.subspan(certSize);
        entriesLength += certSize + 3;
    }

    header[0] = casket::get_byte<1>(entriesLength);
    header[1] = casket::get_byte<2>(entriesLength);
    header[2] = casket::get_byte<3>(entriesLength);

    totalLength += entriesLength;

    return totalLength;
}

} // namespace snet::tls::msg