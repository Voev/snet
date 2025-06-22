#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

void EncryptedExtensions::deserialize(std::span<const uint8_t> buffer)
{
    extensions.deserialize(Side::Server, buffer);
}

size_t EncryptedExtensions::serialize(std::span<uint8_t> buffer) const
{
    return extensions.serialize(Side::Server, buffer);
}

} // namespace snet::tls