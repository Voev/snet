#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/session.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

std::error_code EncryptedExtensions::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    rawExtensions = {};

    utils::DataReader reader(input);

    // Wire form: <2-byte length> <ext>*
    // An empty body (0 bytes) is not valid: there MUST be a 2-byte length.
    const std::uint16_t extLen = reader.get_uint16_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (extLen != reader.remaining_bytes())
    {
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    // keep the whole block, including the 2-byte length
    rawExtensions = input; 
    return reader.take_ec();
}

std::size_t EncryptedExtensions::serialize(nonstd::span<uint8_t> output) const noexcept
{
    // RFC 8446 §4.3.1: extensions is <0..2^16-1>. When there is nothing
    // to send, the wire form is still a 2-byte zero length: 0x00 0x00.
    if (extensions == nullptr)
    {
        if (output.size() < 2)
        {
            return kSerializationFailed;
        }

        output[0] = 0;
        output[1] = 0;
        return 2;
    }

    const auto written = extensions->serialize(Side::Server, output);
    if (written == 0)
    {
        return kSerializationFailed;
    }
    return written;
}

} // namespace snet::tls