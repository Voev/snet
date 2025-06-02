#include <snet/tls/exts/unknown_extension.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

UnknownExtension::UnknownExtension(ExtensionCode type, utils::DataReader& reader, uint16_t extensionSize)
    : type_(type)
    , value_(reader.get_fixed<uint8_t>(extensionSize))
{
}

size_t UnknownExtension::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    (void)whoami;
    ThrowIfTrue(buffer.size_bytes() < value_.size(), "buffer is too small");

    std::copy(value_.begin(), value_.end(), buffer.data());
    return value_.size();
}


} // namespace snet::tls