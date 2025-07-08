#include <snet/crypto/cert.hpp>
#include <snet/crypto/exception.hpp>

#include <snet/tls/msgs/certificate.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

void Certificate::deserialize(const int8_t sideIndex, const ProtocolVersion& version,
                              nonstd::span<const uint8_t> buffer)
{
    static const char* debugInfo = (sideIndex == 0 ? "Client Certificate" : "Server Certificate");
    utils::DataReader reader(debugInfo, buffer);

    if (version == ProtocolVersion::TLSv1_3)
    {
        requestContext_ = reader.get_range<uint8_t>(1, 0, 255);
    }

    const size_t certEntriesLength = reader.get_uint24_t();
    casket::ThrowIfTrue(reader.remaining_bytes() != certEntriesLength, "Certificate: message malformed");

    cert_ = crypto::CertFromMemory(reader.get_span_length_and_value(3));
    crypto::ThrowIfTrue(cert_ == nullptr, "Certificate: decode error");

    if (version == ProtocolVersion::TLSv1_3)
    {
        const auto extensionsLength = reader.get_uint16_t();
        if (extensionsLength > 0)
        {
            certExts_.emplace_back(Extensions((sideIndex == 0) ? Side::Client : Side::Server,
                                              reader.get_span_fixed<uint8_t>(extensionsLength)));
        }
        else
        {
            // Push empty extensions
            certExts_.emplace_back(Extensions());
        }
    }

    if (reader.has_remaining() > 0)
    {
        intermediateCerts_ = crypto::CertStack1Ptr{sk_X509_new_null()};
    }

    while (reader.has_remaining())
    {
        auto ca = crypto::CertFromMemory(reader.get_span_length_and_value(3));
        crypto::ThrowIfTrue(ca == nullptr, "Certificate: decode error");
        sk_X509_push(intermediateCerts_, ca.release());

        if (version == ProtocolVersion::TLSv1_3)
        {
            const auto extensionsLength = reader.get_uint16_t();
            if (extensionsLength > 0)
            {
                certExts_.emplace_back(Extensions((sideIndex == 0) ? Side::Client : Side::Server,
                                                  reader.get_span_fixed<uint8_t>(extensionsLength)));
            }
            else
            {
                // Push empty extensions
                certExts_.emplace_back(Extensions());
            }
        }
    }

    reader.assert_done();
}

size_t Certificate::serialize(const int8_t sideIndex, const ProtocolVersion& version,
                              nonstd::span<uint8_t> buffer) const
{
    (void)sideIndex;

    if (version == ProtocolVersion::TLSv1_3)
    {
        size_t totalLength = 0;

        totalLength += append_length_and_value(buffer, requestContext_.data(), requestContext_.size(), 1);

        auto header = buffer.subspan(totalLength);
        auto entries = header.subspan(3);
        totalLength += 3;

        // uint32_t offset;
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
    return 0;
}

} // namespace snet::tls