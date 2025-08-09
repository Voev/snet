#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

void ServerHello::parse(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("Server Hello", input);

    version = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_span_fixed<uint8_t>(32);
    sessionID = reader.get_span<uint8_t>(1, 0, 32);
    cipherSuite = reader.get_uint16_t();
    compMethod = reader.get_byte();

    auto remaining = reader.get_span_remaining();
    if (version == ProtocolVersion::SSLv3_0)
    {
        if (!remaining.empty())
        {
            extensions = remaining;
        }
        else
        {
            reader.assert_done();
        }
    }
    else
    {
        extensions = remaining;
    }
}

ServerHello ServerHello::deserialize(nonstd::span<const uint8_t> input)
{
    ServerHello serverHello;
    serverHello.parse(input);
    return serverHello;
}

size_t ServerHello::serialize(nonstd::span<uint8_t> output, const Session& session) const
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

    output[0] = casket::get_byte<0>(cipherSuite);
    output[1] = casket::get_byte<1>(cipherSuite);
    output[2] = compMethod;
    output = output.subspan(3);
    length += 3;

    const auto& extensions = session.getServerExtensions();
    offset = extensions.serialize(Side::Server, output);
    length += offset;

    return length;
}

} // namespace snet::tls