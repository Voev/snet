#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

std::error_code ClientHello::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    utils::DataReader reader(input);

    // version: 2 bytes, mandatory
    version = ProtocolVersion(reader.get_uint16_t());
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    // random: exactly 32 bytes
    random = reader.get_span_fixed(32);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    // session_id: <1 byte length> <0..32 bytes>
    sessionID = reader.get_span(1, 0, 32);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    // cipher_suites: <2-byte len> <2..65534 wire bytes, even>.
    const auto suitesRaw = reader.get_span(2, 2, 65534);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (suitesRaw.size() % 2 != 0)
    {
        reader.set_error(utils::DecodeError::SizeNotMultiple);
        return reader.take_ec();
    }

    const std::size_t suiteCount = suitesRaw.size() / 2;
    if (suiteCount > suites.capacity())
    {
        reader.set_error(utils::DecodeError::LengthOutOfRange);
        return reader.take_ec();
    }

    for (std::size_t i = 0; i < suiteCount; ++i)
    {
        suites.push_back(casket::make_uint16(suitesRaw[2 * i], suitesRaw[2 * i + 1]));
    }

    // compression_methods: <1 byte length> <1..255 bytes>
    compMethods = reader.get_span(1, 1, 255);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    // Pre-TLS-1.3 / SSLv3.0: no extensions, must be exactly consumed
    if (version == ProtocolVersion::SSLv3_0)
    {
        reader.assert_done();
        extensions = {};
        return reader.take_ec();
    }

    // Everything else goes to extensions. It is *not* parsed here —
    // Extensions::deserialize() consumes it later, on its own reader.
    extensionsData = reader.get_span_remaining();
    reader.assert_done();

    return reader.take_ec();
}

size_t ClientHello::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (output.size_bytes() < 2)
    {
        return kSerializationFailed;
    }

    size_t pos = 0;
    size_t n = 0;

    output[pos++] = version.majorVersion();
    output[pos++] = version.minorVersion();

    if (output.size_bytes() - pos < random.size())
    {
        return kSerializationFailed;
    }

    if (!random.empty())
    {
        std::memcpy(output.data() + pos, random.data(), random.size());
    }
    pos += random.size();

    n = AppendLengthAndValue(output.subspan(pos), sessionID.data(), sessionID.size(), 1);
    if (n == kSerializationFailed)
    {
        return kSerializationFailed;
    }
    pos += n;

    // cipher_suites: host order -> wire (big-endian).
    {
        const std::size_t suitesBytes = suites.size() * 2;
        if (suitesBytes > 0xFFFF) return kSerializationFailed;
        if (output.size_bytes() - pos < 2 + suitesBytes) return kSerializationFailed;

        output[pos]     = casket::get_byte<0>(static_cast<std::uint16_t>(suitesBytes));
        output[pos + 1] = casket::get_byte<1>(static_cast<std::uint16_t>(suitesBytes));
        pos += 2;

        for (auto id : suites)
        {
            output[pos]     = casket::get_byte<0>(id);
            output[pos + 1] = casket::get_byte<1>(id);
            pos += 2;
        }
    }

    n = AppendLengthAndValue(output.subspan(pos), compMethods.data(), compMethods.size(), 1);
    if (n == kSerializationFailed)
    {
        return kSerializationFailed;
    }
    pos += n;

    if (extensions)
    {
        n = extensions->serialize(Side::Client, output.subspan(pos));
        if (n == 0)
        {
            return kSerializationFailed;
        }
        pos += n;
    }

    return pos;
}

} // namespace snet::tls