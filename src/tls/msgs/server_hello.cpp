#include <snet/tls/msgs/server_hello.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

void ServerHello::deserialize(std::span<const uint8_t> buffer)
{
    utils::DataReader reader("Server Hello", buffer);

    legacyVersion = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_fixed<uint8_t>(32);
    sessionID = reader.get_range<uint8_t>(1, 0, 32);
    cipherSuite = reader.get_uint16_t();
    compMethod = reader.get_byte();

    auto remaining = reader.get_span_remaining();
    if (legacyVersion == ProtocolVersion::SSLv3_0)
    {
        if (!remaining.empty())
        {
            extensions.deserialize(Side::Server, remaining);
        }
        else
        {
            reader.assert_done();
        }
    }
    else
    {
        extensions.deserialize(Side::Server, remaining);
    }
}

size_t ServerHello::serialize(std::span<uint8_t> buffer) const
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

    buffer[0] = utils::get_byte<0>(cipherSuite);
    buffer[1] = utils::get_byte<1>(cipherSuite);
    buffer[2] = compMethod;
    buffer = buffer.subspan(3);
    length += 3;

    offset = extensions.serialize(Side::Server, buffer);
    length += offset;

    return length;
}

} // namespace snet::tls