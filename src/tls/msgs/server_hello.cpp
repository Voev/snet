#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

// SHA-256("HelloRetryRequest")
const std::array<uint8_t, TLS_RANDOM_SIZE> HELLO_RETRY_REQUEST_MARKER = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

static inline bool checkForHRR(nonstd::span<const uint8_t> random)
{
    assert(random.size() == TLS_RANDOM_SIZE);
    return std::equal(HELLO_RETRY_REQUEST_MARKER.begin(), HELLO_RETRY_REQUEST_MARKER.end(), random.begin());
}

void ServerHello::parse(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("Server Hello", input);

    version = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_span_fixed(TLS_RANDOM_SIZE);

    /// TLSv1.3 HelloRetryRequest checking
    if (version == ProtocolVersion::TLSv1_2)
    {
        isHelloRetryRequest = checkForHRR(random);
    }

    sessionID = reader.get_span(1, 0, 32);
    cipherSuite = reader.get_uint16_t();
    compMethod = reader.get_byte();

    if (version == ProtocolVersion::SSLv3_0)
    {
        if (reader.remaining_bytes() > 0)
        {
            auto extensionsLength = reader.peek_uint16_t();
            casket::ThrowIfFalse(extensionsLength == reader.remaining_bytes() - 2, "Invalid extesions length");
            extensions = reader.get_span_remaining();
        }
    }
    else
    {
        auto extensionsLength = reader.peek_uint16_t();
        casket::ThrowIfFalse(extensionsLength == reader.remaining_bytes() - 2, "Invalid extesions length");
        extensions = reader.get_span_remaining();
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