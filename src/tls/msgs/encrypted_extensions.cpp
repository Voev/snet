#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

void EncryptedExtensions::parse(nonstd::span<const uint8_t> input)
{
    extensions = input;
}

EncryptedExtensions EncryptedExtensions::deserialize(nonstd::span<const uint8_t> input)
{
    EncryptedExtensions encryptedExtensions;
    encryptedExtensions.parse(input);
    return encryptedExtensions;
}

size_t EncryptedExtensions::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    const auto& extensions = session.getEncryptedExtensions();
    return extensions.serialize(Side::Server, output);
}

} // namespace snet::tls