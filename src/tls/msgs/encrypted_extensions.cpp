#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/session.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

std::error_code EncryptedExtensions::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    extensions = {};

    utils::DataReader reader("EncryptedExtensions", input);

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

    extensions = input; // keep the whole block, including the 2-byte length
    reader.assert_done();
    return reader.take_ec();
}

std::size_t EncryptedExtensions::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    const auto written = session.getEncryptedExtensions().serialize(Side::Server, output);
    if (written == 0)
    {
        return kSerializationFailed;
    }
    return written;
}

} // namespace snet::tls