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

EncryptThenMAC::EncryptThenMAC(std::span<const uint8_t> input)
{
    ThrowIfFalse(input.empty(), "invalid encrypt_then_mac extension");
}

size_t EncryptThenMAC::serialize(Side side, std::span<uint8_t> output) const
{
    (void)side;
    (void)output;
    return 0;
}

bool EncryptThenMAC::empty() const
{
    return false;
}

} // namespace snet::tls