#include <snet/tls/exts/server_name_indication.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

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

ServerNameIndicator::ServerNameIndicator(std::string_view hostname)
    : hostname_(hostname)
{
}

ServerNameIndicator::ServerNameIndicator(utils::DataReader& reader, uint16_t extensionSize)
{
    // This is used by the server to confirm that it knew the name
    if (extensionSize == 0)
    {
        return;
    }

    uint16_t nameBytes = reader.get_uint16_t();
    ThrowIfTrue(nameBytes + 2 != extensionSize, "bad encoding of SNI extension");

    while (nameBytes)
    {
        uint8_t name_type = reader.get_byte();
        nameBytes--;

        if (name_type == 0)
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
}

size_t ServerNameIndicator::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    // RFC 6066
    //    [...] the server SHALL include an extension of type "server_name" in
    //    the (extended) server hello. The "extension_data" field of this
    //    extension SHALL be empty.
    if (whoami == Side::Server)
    {
        return 0;
    }

    size_t nameLength = hostname_.size();
    ThrowIfTrue(buffer.size_bytes() < 5 + nameLength, "buffer is too small");

    buffer[0] = utils::get_byte<0>(static_cast<uint16_t>(nameLength + 3));
    buffer[1] = utils::get_byte<1>(static_cast<uint16_t>(nameLength + 3));
    buffer[2] = 0; // DNS

    buffer[3] = utils::get_byte<0>(static_cast<uint16_t>(nameLength));
    buffer[4] = utils::get_byte<1>(static_cast<uint16_t>(nameLength));
    buffer = buffer.subspan(5);

    std::copy(hostname_.begin(), hostname_.end(), buffer.begin());
    return 5 + nameLength;
}

std::string ServerNameIndicator::host_name() const
{
    return hostname_;
}

bool ServerNameIndicator::empty() const
{
    return false;
}

} // namespace snet::tls