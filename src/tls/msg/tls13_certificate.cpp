#include <snet/tls/msg/tls13_certificate.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls::msg
{

void TLSv13Certificate::deserialize(std::span<const uint8_t> buffer)
{
    utils::DataReader reader("TLSv1.3 Certificate", buffer);

    requestContext = reader.get_range<uint8_t>(1, 0, 255);

    const size_t certEntriesLength = reader.get_uint24_t();
    ::utils::ThrowIfTrue(reader.remaining_bytes() != certEntriesLength, "TLSv1.3 Certificate: message malformed");

    while (reader.has_remaining())
    {
        certs.emplace_back(reader.get_tls_length_value(3));

        Extensions exts;
        exts.deserialize(reader, Side::Client, HandshakeType::ClientHello);
        certExts.emplace_back(std::move(exts));
    }

    reader.assert_done();
}

size_t TLSv13Certificate::serialize(std::span<uint8_t> buffer) const
{
    size_t totalLength = 0;

    totalLength += utils::append_tls_length_value(buffer, requestContext.data(), requestContext.size(), 1);

    auto header = buffer.subspan(totalLength);
    auto entries = header.subspan(3);
    totalLength += 3;

    uint32_t offset;
    uint32_t entriesLength{0};
    for (size_t i = 0; i < certs.size(); ++i)
    {
        offset = utils::append_tls_length_value(entries, certs[i].data(), certs[i].size(), 3);
        entries = entries.subspan(offset);
        entriesLength += offset;

        offset = certExts[i].serialize(Side::Client, entries);
        entries = entries.subspan(offset);
        entriesLength += offset;
    }

    header[0] = utils::get_byte<1>(entriesLength);
    header[1] = utils::get_byte<2>(entriesLength);
    header[2] = utils::get_byte<3>(entriesLength);

    totalLength += entriesLength;

    return totalLength;
}

} // namespace snet::tls::msg