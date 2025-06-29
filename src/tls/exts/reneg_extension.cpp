#include <snet/tls/exts/reneg_extension.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

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

bool RenegotiationExtension::empty() const
{
    return false;
}

size_t RenegotiationExtension::serialize(Side side, nonstd::span<uint8_t> output) const
{
    (void)side;
    return append_length_and_value(output, renegData_.data(), renegData_.size(), 1);
}

RenegotiationExtension::RenegotiationExtension(const std::vector<uint8_t>& renegData)
    : renegData_(renegData)
{
}

RenegotiationExtension::RenegotiationExtension(Side side, nonstd::span<const uint8_t> input)
{
    (void)side;

    utils::DataReader reader("renegotiation_extension", input);
    renegData_ = reader.get_range<uint8_t>(1, 0, 255);
    reader.assert_done();
}

const std::vector<uint8_t>& RenegotiationExtension::getRenegInfo() const
{
    return renegData_;
}

} // namespace snet::tls