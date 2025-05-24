#include <snet/tls/msg/encrypted_extensions.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls::msg
{

void EncryptedExtensions::deserialize(std::span<const uint8_t> buffer)
{
    utils::DataReader reader("Encrypted extensions", buffer);
    extensions.deserialize(reader, Side::Server, HandshakeType::EncryptedExtensions);
    reader.assert_done();
}

size_t EncryptedExtensions::serialize(std::span<uint8_t> buffer) const
{
    return extensions.serialize(Side::Server, buffer);
}

} // namespace snet::tls::msg