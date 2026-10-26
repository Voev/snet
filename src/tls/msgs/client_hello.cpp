#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

utils::DecodeError ClientHello::parse(nonstd::span<const uint8_t> input) noexcept
{
    utils::DataReader reader("Client Hello", input);

    // version: 2 bytes, mandatory
    version = ProtocolVersion(reader.get_uint16_t());
    if (!reader.ok())
    {
        return reader.take_error();
    }

    // random: exactly 32 bytes
    random = reader.get_span_fixed(32);
    if (!reader.ok())
    {
        return reader.take_error();
    }

    // session_id: <1 byte length> <0..32 bytes>
    sessionID = reader.get_span(1, 0, 32);
    if (!reader.ok())
    {
        return reader.take_error();
    }

    // cipher_suites: <2 byte length> <2..65534 bytes, even>  (RFC: 2..2^16-2)
    suites = reader.get_span(2, 2, 65534);
    if (!reader.ok())
    {
        return reader.take_error();
    }

    if (suites.size() % 2 != 0)
    {
        // must be multiple of 2
        reader.set_error(utils::DecodeError::SizeNotMultiple);
        return reader.take_error();
    }

    // compression_methods: <1 byte length> <1..255 bytes>
    compMethods = reader.get_span(1, 1, 255);
    if (!reader.ok())
    {
        return reader.take_error();
    }

    // Pre-TLS-1.3 / SSLv3.0: no extensions, must be exactly consumed
    if (version == ProtocolVersion::SSLv3_0)
    {
        reader.assert_done();
        extensions = {};
        return reader.take_error();
    }

    // Everything else goes to extensions. It is *not* parsed here —
    // Extensions::deserialize() consumes it later, on its own reader.
    extensions = reader.get_span_remaining();
    reader.assert_done();

    return reader.take_error();
}

ClientHello ClientHello::deserialize(nonstd::span<const uint8_t> input)
{
    ClientHello msg;
    const auto err = msg.parse(input);
    if (err != utils::DecodeError::None)
    {
        throw casket::RuntimeError(std::string("ClientHello: ") + utils::make_error_code(err).message());
    }
    return msg;
}

size_t ClientHello::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    size_t offset{};
    size_t length{};

    output[0] = version.majorVersion();
    output[1] = version.minorVersion();
    output = output.subspan(2);
    length += 2;

    std::copy(random.begin(), random.end(), output.begin());
    output = output.subspan(random.size());
    length += random.size();

    offset = append_length_and_value(output, sessionID.data(), sessionID.size(), 1);
    output = output.subspan(offset);
    length += offset;

    offset = append_length_and_value(output, suites.data(), suites.size(), 2);
    output = output.subspan(offset);
    length += offset;

    offset = append_length_and_value(output, compMethods.data(), compMethods.size(), 1);
    output = output.subspan(offset);
    length += offset;

    const auto& extensions = session.getClientExtensions();
    offset = extensions.serialize(Side::Client, output);
    output = output.subspan(offset);
    length += offset;

    return length;
}

} // namespace snet::tls