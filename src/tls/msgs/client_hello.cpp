#include <snet/tls/msgs/client_hello.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls
{

void ClientHello::deserialize(nonstd::span<const uint8_t> message)
{
    utils::DataReader reader("Client Hello", message);

    legacyVersion = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_fixed<uint8_t>(32);
    sessionID = reader.get_range<uint8_t>(1, 0, 32);
    suites = reader.get_range_vector<uint16_t>(2, 1, 32767);
    compMethods = reader.get_range_vector<uint8_t>(1, 1, 255);

    if (legacyVersion == ProtocolVersion::SSLv3_0)
    {
        reader.assert_done();
    }
    else
    {
        extensions.deserialize(Side::Client, reader.get_span_remaining());
    }
}

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

void ClientHello::print(std::ostream& os) const
{
    os << "Version: " << legacyVersion.toString() << "\n";

    utils::printHex(os, random, "Random:");
    utils::printHex(os, sessionID, "Session ID:");

    os << "Cipher Suites:\n";
    os << std::hex << std::setw(2) << std::setfill('0');
    for (const auto& cipherSuite : suites)
    {
        os << "  0x" << (int)casket::get_byte<0>(cipherSuite) << ", 0x" << (int)casket::get_byte<1>(cipherSuite) << "\n";
    }
    os << std::dec;

    utils::printHex(os, compMethods, "Compression:");
    os << "Extensions:\n";
    for (const auto& ext : extensions.all())
    {
        uint8_t buffer[256];
        size_t length = ext->serialize(Side::Client, buffer);
        utils::printHex(os, {buffer, length}, std::to_string((int)ext->type()));
    }
}

} // namespace snet::tls