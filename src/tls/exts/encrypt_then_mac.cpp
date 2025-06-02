#include <snet/tls/exts/encrypt_then_mac.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

ExtensionCode EncryptThenMAC::staticType()
{
    return ExtensionCode::EncryptThenMac;
}

ExtensionCode EncryptThenMAC::type() const
{
    return staticType();
}

EncryptThenMAC::EncryptThenMAC(utils::DataReader& reader, uint16_t extensionSize)
{
    (void)reader;
    ThrowIfTrue(extensionSize != 0, "invalid encrypt_then_mac extension");
}

size_t EncryptThenMAC::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    (void)whoami;
    (void)buffer;
    return 0;
}

bool EncryptThenMAC::empty() const
{
    return false;
}

} // namespace snet::tls