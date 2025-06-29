#include <snet/tls/exts/extended_master_secret.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

ExtensionCode ExtendedMasterSecret::staticType()
{
    return ExtensionCode::ExtendedMasterSecret;
}

ExtensionCode ExtendedMasterSecret::type() const
{
    return staticType();
}

ExtendedMasterSecret::ExtendedMasterSecret(cpp::span<const uint8_t> input)
{
    ThrowIfFalse(input.empty(), "invalid extended_master_secret extension");
}

size_t ExtendedMasterSecret::serialize(Side side, cpp::span<uint8_t> output) const
{
    (void)side;
    (void)output;
    return 0;
}

bool ExtendedMasterSecret::empty() const
{
    return false;
}

} // namespace snet::tls