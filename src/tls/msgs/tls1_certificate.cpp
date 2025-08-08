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

size_t TLSv1Certificate::serialize(nonstd::span<uint8_t> buffer) const
{
    size_t totalLength{0};

    auto header = buffer.subspan(totalLength);
    auto entries = header.subspan(3);
    totalLength += 3;

    //uint32_t offset;
    uint32_t entriesLength{0};
    /*for (size_t i = 0; i < certs.size(); ++i)
    {
        offset = append_length_and_value(entries, certs[i].data(), certs[i].size(), 3);
        entries = entries.subspan(offset);
        entriesLength += offset;

        offset = certExts[i].serialize(side, entries);
        entries = entries.subspan(offset);
        entriesLength += offset;
    }*/

    header[0] = casket::get_byte<1>(entriesLength);
    header[1] = casket::get_byte<2>(entriesLength);
    header[2] = casket::get_byte<3>(entriesLength);

    totalLength += entriesLength;

    return totalLength;
}

} // namespace snet::tls::msg