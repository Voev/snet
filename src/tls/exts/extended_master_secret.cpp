#include <snet/tls/exts/extended_master_secret.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

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

ExtendedMasterSecret::ExtendedMasterSecret(utils::DataReader& reader, uint16_t extensionSize)
{
    (void)reader;
    ThrowIfTrue(extensionSize != 0, "invalid extended_master_secret extension");
}

size_t ExtendedMasterSecret::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    (void)whoami;
    (void)buffer;
    return 0;
}

bool ExtendedMasterSecret::empty() const
{
    return false;
}

} // namespace snet::tls