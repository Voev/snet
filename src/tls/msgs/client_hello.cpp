#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{



void ClientHello::parse(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("Client Hello", input);

    /// @todo: fuzzing: check bytes for correctness
    version = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_span_fixed<uint8_t>(32);
    sessionID = reader.get_span<uint8_t>(1, 0, 32);
    suites = reader.get_span<uint16_t>(2, 1, 32767);
    compMethods = reader.get_span<uint8_t>(1, 1, 255);

    if (version == ProtocolVersion::SSLv3_0)
    {
        reader.assert_done();
    }
    else
    {
        extensions = reader.get_span_remaining();
    }
}

ClientHello ClientHello::deserialize(nonstd::span<const uint8_t> input)
{
    ClientHello msg;
    msg.parse(input);
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