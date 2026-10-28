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

    // cipher_suites: <2 byte length> <2..65534 bytes, even>  (RFC: 2..2^16-2)
    suites = reader.get_span(2, 2, 65534);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (suites.size() % 2 != 0)
    {
        // must be multiple of 2
        reader.set_error(utils::DecodeError::SizeNotMultiple);
        return reader.take_ec();
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
    extensions = reader.get_span_remaining();
    reader.assert_done();

    return reader.take_ec();
}

size_t ClientHello::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
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

    n = AppendLengthAndValue(output.subspan(pos), suites.data(), suites.size(), 2);
    if (n == kSerializationFailed)
    {
        return kSerializationFailed;
    }
    pos += n;

    n = AppendLengthAndValue(output.subspan(pos), compMethods.data(), compMethods.size(), 1);
    if (n == kSerializationFailed)
    {
        return kSerializationFailed;
    }
    pos += n;

    const auto extWritten = session.getClientExtensions().serialize(Side::Client, output.subspan(pos));
    if (extWritten == 0)
    {
        return kSerializationFailed;
    }

    return pos + extWritten;
}

} // namespace snet::tls