#include <snet/tls/exts/supported_point_formats.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

SupportedPointFormats::SupportedPointFormats(const std::vector<ECPointFormat>& formats)
    : formats_(formats)
{
}

size_t SupportedPointFormats::serialize(Side side, std::span<uint8_t> output) const
{
    (void)side;
    return append_length_and_value(output, formats_.data(), formats_.size(), 1);
}

SupportedPointFormats::SupportedPointFormats(Side side, std::span<const uint8_t> input)
{
    (void)side;

    utils::DataReader reader("ec_point_formats extension", input);
    uint8_t len = reader.get_byte();

    ThrowIfFalse(len == reader.remaining_bytes(), "inconsistent length field in supported point formats list");

    for (size_t i = 0; i != len; ++i)
    {
        /// @todo: check correctness for byte
        formats_.push_back(static_cast<ECPointFormat>(reader.get_byte()));
    }
}

} // namespace snet::tls