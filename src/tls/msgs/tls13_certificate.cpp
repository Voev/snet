#include <snet/tls/msgs/tls13_certificate.hpp>

#include <snet/crypto/cert.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv13Certificate::deserialize(nonstd::span<const uint8_t> buffer)
{
    utils::DataReader reader("TLSv1.3 Certificate", buffer);

    requestContext = reader.get_span(1, 0, 255);

    const size_t certEntriesLength = reader.get_uint24_t();
    ThrowIfTrue(reader.remaining_bytes() != certEntriesLength, "TLSv1.3 Certificate: message malformed");

    while (reader.has_remaining())
    {
        Entry entry;
        entry.certData = reader.get_span_length_and_value(3);

        const auto length = reader.peek_uint16_t();
        entry.extsData = reader.get_span_fixed(2 + length);

        entryList[entryCount++] = std::move(entry);
    }

    reader.assert_done();
}

size_t TLSv13Certificate::serialize(nonstd::span<uint8_t> output) const
{
    size_t totalLength{0};

    totalLength += append_length_and_value(output, requestContext.data(), requestContext.size(), 1);

    auto header = output.subspan(totalLength);
    auto entries = header.subspan(3);
    totalLength += 3;

    int32_t offset;
    uint32_t entriesLength{0};
    for (size_t i = 0; i < entryCount; ++i)
    {
        auto certData = entries.subspan(3);

        offset = crypto::Cert::toBuffer(entryList[i].cert, certData);
        ThrowIfTrue(offset < 0, "Certificate serialization error");

        entries[0] = casket::get_byte<1>(offset);
        entries[1] = casket::get_byte<2>(offset);
        entries[2] = casket::get_byte<3>(offset);

        offset += 3;
        entries = entries.subspan(offset);
        entriesLength += offset;

        if (entryList[i].extensions)
        {
            /// @todo: pay attention to side
            offset = entryList[i].extensions->serialize(Side::Server, entries);
        }
        else
        {
            offset = 2;
            entries[0] = 0x00;
            entries[1] = 0x00;
        }

        entries = entries.subspan(offset);
        entriesLength += offset;
    }

    header[0] = casket::get_byte<1>(entriesLength);
    header[1] = casket::get_byte<2>(entriesLength);
    header[2] = casket::get_byte<3>(entriesLength);

    totalLength += entriesLength;

    return totalLength;
}

} // namespace snet::tls