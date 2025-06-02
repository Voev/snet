#include <snet/tls/exts/reneg_extension.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

ExtensionCode RenegotiationExtension::staticType()
{
    return ExtensionCode::SafeRenegotiation;
}

ExtensionCode RenegotiationExtension::type() const
{
    return staticType();
}

RenegotiationExtension::RenegotiationExtension(const std::vector<uint8_t>& bits)
    : renegData_(bits)
{
}

RenegotiationExtension::RenegotiationExtension(utils::DataReader& reader, uint16_t extensionSize)
    : renegData_(reader.get_range<uint8_t>(1, 0, 255))
{
    ThrowIfFalse(renegData_.size() + 1 == extensionSize, "bad encoding for secure renegotiation extension");
}

size_t RenegotiationExtension::serialize(Side side, std::span<uint8_t> buffer) const
{
    (void)side;
    return append_length_and_value(buffer, renegData_.data(), renegData_.size(), 1);
}

const std::vector<uint8_t>& RenegotiationExtension::renegotiation_info() const
{
    return renegData_;
}

bool RenegotiationExtension::empty() const
{
    return false;
}

} // namespace snet::tls