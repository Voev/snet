#include <snet/tls/msgs/server_hello.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

void ServerHello::deserialize(nonstd::span<const uint8_t> input)
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

/*
size_t ServerHello::serialize(nonstd::span<uint8_t> buffer) const
{
    size_t offset{};
    size_t length{};

    buffer[0] = version.majorVersion();
    buffer[1] = version.minorVersion();
    buffer = buffer.subspan(2);
    length += 2;

    std::copy(random.begin(), random.end(), buffer.begin());
    buffer = buffer.subspan(random.size());
    length += random.size();

    offset = append_length_and_value(buffer, sessionID.data(), sessionID.size(), 1);
    buffer = buffer.subspan(offset);
    length += offset;

    buffer[0] = casket::get_byte<0>(cipherSuite);
    buffer[1] = casket::get_byte<1>(cipherSuite);
    buffer[2] = compMethod;
    buffer = buffer.subspan(3);
    length += 3;

    offset = extensions.serialize(Side::Server, buffer);
    length += offset;

    return length;
}*/

} // namespace snet::tls