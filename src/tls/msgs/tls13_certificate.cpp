#include <snet/tls/msgs/tls13_certificate.hpp>

#include <cstring>

#include <casket/utils/load_store.hpp>

#include <snet/crypto/cert.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <snet/tls/session.hpp>

using namespace snet::utils;

namespace snet::tls
{

std::error_code TLSv13Certificate::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    requestContext = {};
    entryCount = 0;
    for (auto& e : entryList)
    {
        e.certData = {};
        e.extsData = {};
        e.cert = nullptr;
    }

    utils::DataReader reader(input);

    requestContext = reader.get_span(1, 0, 255);
    if (!reader.ok())
        return reader.take_ec();

    const std::uint32_t total = reader.get_uint24_t();
    if (!reader.ok())
        return reader.take_ec();
    if (total != reader.remaining_bytes())
        return make_error_code(DecodeError::LengthOutOfRange);

    while (reader.has_remaining())
    {
        if (entryCount == kMaxCertChain)
            return make_error_code(DecodeError::LengthOutOfRange);

        Entry& entry = entryList[entryCount];

        entry.certData = reader.get_span_length_and_value(3);
        if (!reader.ok())
        {
            entryCount = 0;
            return reader.take_ec();
        }
        if (entry.certData.empty())
        {
            entryCount = 0;
            return make_error_code(DecodeError::LengthOutOfRange);
        }

        const std::uint16_t extTotal = reader.peek_uint16_t();
        if (!reader.ok())
        {
            entryCount = 0;
            return reader.take_ec();
        }
        if (static_cast<std::size_t>(extTotal) + 2 > reader.remaining_bytes())
        {
            entryCount = 0;
            return make_error_code(DecodeError::LengthOutOfRange);
        }
        entry.extsData = reader.get_span_fixed(2 + static_cast<std::size_t>(extTotal));
        if (!reader.ok())
        {
            entryCount = 0;
            return reader.take_ec();
        }

        ++entryCount;
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv13Certificate::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    (void)session;
    /// @todo: from session.getSide();
    const Side side = Side::Server;
    std::size_t pos = 0;

    // certificate_request_context
    if (output.size_bytes() < 1)
        return kSerializationFailed;
    if (requestContext.size() > 255)
        return kSerializationFailed;
    output[pos++] = static_cast<std::uint8_t>(requestContext.size());
    if (!requestContext.empty())
    {
        if (output.size_bytes() - pos < requestContext.size())
            return kSerializationFailed;
        std::memcpy(output.data() + pos, requestContext.data(), requestContext.size());
        pos += requestContext.size();
    }

    if (output.size_bytes() - pos < 3)
        return kSerializationFailed;
    const std::size_t listStart = pos;
    pos += 3;

    std::uint32_t entriesLength = 0;

    for (std::size_t i = 0; i < entryCount; ++i)
    {
        const Entry& entry = entryList[i];
        if (!entry.cert)
            return kSerializationFailed;

        if (output.size_bytes() - pos < 3)
            return kSerializationFailed;
        auto certBuf = output.subspan(pos + 3);

        const auto certSize = crypto::Cert::toBuffer(entry.cert, certBuf);
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

        // extensions
        if (entry.extensions)
        {
            const auto n = entry.extensions->serialize(side, output.subspan(pos));
            if (n == 0)
                return kSerializationFailed;
            pos += n;
            entriesLength += static_cast<std::uint32_t>(n);
        }
        else
        {
            if (entry.extsData.size() < 2)
                return kSerializationFailed;
            if (output.size_bytes() - pos < entry.extsData.size())
                return kSerializationFailed;
            std::memcpy(output.data() + pos, entry.extsData.data(), entry.extsData.size());
            pos += entry.extsData.size();
            entriesLength += static_cast<std::uint32_t>(entry.extsData.size());
        }
    }

    if (entriesLength > 0xFFFFFF)
        return kSerializationFailed;
    output[listStart] = casket::get_byte<1>(entriesLength);
    output[listStart + 1] = casket::get_byte<2>(entriesLength);
    output[listStart + 2] = casket::get_byte<3>(entriesLength);

    return pos;
}

} // namespace snet::tls