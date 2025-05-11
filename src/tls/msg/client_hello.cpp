#include <snet/tls/msg/client_hello.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/print_hex.hpp>

namespace snet::tls::msg
{

void ClientHello::deserialize(std::span<const uint8_t> message)
{
    utils::DataReader reader("Client Hello", message);

    legacyVersion = ProtocolVersion(reader.get_uint16_t());
    random = reader.get_fixed<uint8_t>(32);
    sessionID = reader.get_range<uint8_t>(1, 0, 32);
    suites = reader.get_range_vector<uint16_t>(2, 1, 32767);
    compMethods = reader.get_range_vector<uint8_t>(1, 1, 255);
    extensions.deserialize(reader, Side::Client, HandshakeType::ClientHello);

    reader.assert_done();
}

size_t ClientHello::serialize(std::span<uint8_t> buffer) const
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

    offset = utils::append_tls_length_value(buffer, sessionID.data(), sessionID.size(), 1);
    buffer = buffer.subspan(offset);
    length += offset;

    offset = utils::append_tls_length_value(buffer, suites.data(), suites.size(), 2);
    buffer = buffer.subspan(offset);
    length += offset;

    offset = utils::append_tls_length_value(buffer, compMethods.data(), compMethods.size(), 1);
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
    
    utils::printHex(os, "Random:", random);
    utils::printHex(os, "Session ID:", sessionID);

    os << "Cipher Suites:\n";
    os << std::hex << std::setw(2) << std::setfill('0');
    for(const auto& cipherSuite : suites)
    {
        os << "  0x" << (int)utils::get_byte<0>(cipherSuite) 
           << ", 0x" << (int)utils::get_byte<1>(cipherSuite) << "\n";
    }
    os << std::dec;

    utils::printHex(os, "Compression:", compMethods);
    os << "Extensions:\n";
    for (const auto& ext : extensions.all())
    {
        uint8_t buffer[256];
        size_t length = ext->serialize(Side::Client, buffer);
        utils::printHex(os, std::to_string((int)ext->type()), {buffer, length});
    }
}

} // namespace snet::tls::msg