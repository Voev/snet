#include <snet/tls/msgs/client_hello.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

void ClientHello::deserialize(nonstd::span<const uint8_t> input)
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

/*
size_t ClientHello::serialize(nonstd::span<uint8_t> buffer) const
{
    size_t offset{};
    size_t length{};

    buffer[0] = legacyVersion.majorVersion();
    buffer[1] = legacyVersion.minorVersion();
    buffer = buffer.subspan(2);
    length += 2;

    std::copy(random.begin(), random.end(), buffer.begin());
    buffer = buffer.subspan(random.size());
    length += random.size();

    offset = append_length_and_value(buffer, sessionID.data(), sessionID.size(), 1);
    buffer = buffer.subspan(offset);
    length += offset;

    offset = append_length_and_value(buffer, suites.data(), suites.size(), 2);
    buffer = buffer.subspan(offset);
    length += offset;

    offset = append_length_and_value(buffer, compMethods.data(), compMethods.size(), 1);
    buffer = buffer.subspan(offset);
    length += offset;

    offset = extensions.serialize(Side::Client, buffer);
    buffer = buffer.subspan(offset);
    length += offset;

    return length;
}
    */

} // namespace snet::tls