#include <snet/tls/msgs/tls1_certificate.hpp>

#include <cstring>

#include <casket/utils/load_store.hpp>

#include <snet/crypto/cert.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

namespace
{

inline std::error_code ec(utils::DecodeError e) noexcept
{
    return utils::make_error_code(e);
}

} // namespace

std::error_code TLSv1Certificate::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    entryCount = 0;
    for (auto& e : entryList)
    {
        e.certData = {};
        e.cert = nullptr;
    }

    utils::DataReader reader("Certificate", input);

    const std::uint32_t total = reader.get_uint24_t();
    if (!reader.ok())
        return reader.take_ec();
    if (total != reader.remaining_bytes())
        return ec(utils::DecodeError::LengthOutOfRange);

    while (reader.has_remaining())
    {
        if (entryCount == kMaxCertChain)
        {
            return ec(utils::DecodeError::LengthOutOfRange); // too many certificates
        }

        const auto certData = reader.get_span_length_and_value(3);
        if (!reader.ok())
        {
            entryCount = 0;
            return reader.take_ec();
        }
        if (certData.empty())
        {
            entryCount = 0;
            return ec(utils::DecodeError::LengthOutOfRange);
        }

        entryList[entryCount].certData = certData;
        ++entryCount;
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv1Certificate::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (output.size_bytes() < 3)
        return kSerializationFailed;

    std::size_t pos = 3; // reserve for <3-byte total length>
    std::uint32_t entriesLength = 0;

    for (std::size_t i = 0; i < entryCount; ++i)
    {
        if (!entryList[i].cert)
            return kSerializationFailed;

        if (output.size_bytes() - pos < 3)
            return kSerializationFailed;
        auto certBuf = output.subspan(pos + 3);

        const auto certSize = crypto::Cert::toBuffer(entryList[i].cert, certBuf);
        if (certSize < 0)
            return kSerializationFailed;
        if (static_cast<std::size_t>(certSize) > 0xFFFFFF)
            return kSerializationFailed;

        const auto certSize32 = static_cast<std::uint32_t>(certSize);
        output[pos] = casket::get_byte<1>(certSize32);
        output[pos + 1] = casket::get_byte<2>(certSize32);
        output[pos + 2] = casket::get_byte<3>(certSize32);

        pos += 3 + static_cast<std::size_t>(certSize);
        entriesLength += 3 + certSize32;
    }

    if (entriesLength > 0xFFFFFF)
        return kSerializationFailed;

    output[0] = casket::get_byte<1>(entriesLength);
    output[1] = casket::get_byte<2>(entriesLength);
    output[2] = casket::get_byte<3>(entriesLength);

    return pos;
}

} // namespace snet::tls