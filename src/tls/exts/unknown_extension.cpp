#include <snet/tls/exts/unknown_extension.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

ExtensionCode UnknownExtension::type() const
{
    return type_;
}

bool UnknownExtension::empty() const
{
    return false;
}

size_t UnknownExtension::serialize(Side side, nonstd::span<uint8_t> output) const
{
    (void)side;

    ThrowIfTrue(output.size_bytes() < value_.size(), "buffer is too small");
    std::copy(value_.begin(), value_.end(), output.data());
    return value_.size();
}

UnknownExtension::UnknownExtension(ExtensionCode type, nonstd::span<const uint8_t> input)
    : type_(type)
    , value_(input.begin(), input.end())
{
}

const std::vector<uint8_t>& UnknownExtension::value()
{
    return value_;
}

} // namespace snet::tls