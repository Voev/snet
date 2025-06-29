#include <snet/tls/exts/server_name_indication.hpp>
#include <snet/utils/data_reader.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

ExtensionCode ServerNameIndicator::staticType()
{
    return ExtensionCode::ServerNameIndication;
}

ExtensionCode ServerNameIndicator::type() const
{
    return staticType();
}

bool ServerNameIndicator::empty() const
{
    return false;
}

size_t ServerNameIndicator::serialize(Side side, nonstd::span<uint8_t> output) const
{
    // RFC 6066
    //    [...] the server SHALL include an extension of type "server_name" in
    //    the (extended) server hello. The "extension_data" field of this
    //    extension SHALL be empty.
    if (side == Side::Server)
    {
        return 0;
    }

    size_t nameLength = hostname_.size();
    ThrowIfTrue(output.size_bytes() < 5 + nameLength, "buffer is too small");

    output[0] = casket::get_byte<0>(static_cast<uint16_t>(nameLength + 3));
    output[1] = casket::get_byte<1>(static_cast<uint16_t>(nameLength + 3));
    output[2] = 0; // DNS

    output[3] = casket::get_byte<0>(static_cast<uint16_t>(nameLength));
    output[4] = casket::get_byte<1>(static_cast<uint16_t>(nameLength));
    output = output.subspan(5);

    std::copy(hostname_.begin(), hostname_.end(), output.begin());
    return 5 + nameLength;
}

ServerNameIndicator::ServerNameIndicator(std::string_view hostname)
    : hostname_(hostname)
{
}

ServerNameIndicator::ServerNameIndicator(Side side, nonstd::span<const uint8_t> input)
{
    (void)side;

    // This is used by the server to confirm that it knew the name
    if (input.empty())
    {
        return;
    }

    utils::DataReader reader("SNI", input);
    uint16_t nameBytes = reader.get_uint16_t();
    ThrowIfTrue(nameBytes != reader.remaining_bytes(), "bad encoding of SNI extension");

    while (nameBytes)
    {
        uint8_t nameType = reader.get_byte();
        nameBytes--;

        if (nameType == 0)
        {
            // DNS
            hostname_ = reader.get_string(2, 1, 65535);
            nameBytes -= static_cast<uint16_t>(2 + hostname_.size());
        }
        else
        {
            // some other unknown name type, which we will ignore
            reader.discard_next(nameBytes);
            nameBytes = 0;
        }
    }

    reader.assert_done();
}

const std::string& ServerNameIndicator::getHostname() const
{
    return hostname_;
}

} // namespace snet::tls