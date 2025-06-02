#include <snet/tls/exts/alpn.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

ExtensionCode ALPN::staticType()
{
    return ExtensionCode::AppLayerProtocolNegotiation;
}

ExtensionCode ALPN::type() const
{
    return staticType();
}

ALPN::ALPN(std::string_view protocol)
    : protocols_(1, std::string(protocol))
{
}

ALPN::ALPN(const std::vector<std::string>& protocols)
    : protocols_(protocols)
{
}

ALPN::ALPN(utils::DataReader& reader, uint16_t extensionSize, Side from)
{
    if (extensionSize == 0)
    {
        return;
    }

    const uint16_t nameBytes = reader.get_uint16_t();
    size_t bytesRemaining = extensionSize - 2;

    ThrowIfTrue(nameBytes != bytesRemaining, "bad encoding of ALPN extension, bad length field");

    while (bytesRemaining)
    {
        const std::string p = reader.get_string(1, 0, 255);

        ThrowIfTrue(bytesRemaining < p.size() + 1, "bad encoding of ALPN, length field too long");
        ThrowIfTrue(p.empty(), "empty ALPN protocol not allowed");

        bytesRemaining -= (p.size() + 1);

        protocols_.push_back(p);
    }

    // RFC 7301 3.1
    //    The "extension_data" field of the [...] extension is structured the
    //    same as described above for the client "extension_data", except that
    //    the "ProtocolNameList" MUST contain exactly one "ProtocolName".
    ThrowIfTrue(from == Side::Server && protocols_.size() != 1, "server sent {} protocols in ALPN extension response",
                protocols_.size());
}

size_t ALPN::serialize(Side side, std::span<uint8_t> buffer) const
{
    (void)side;

    ThrowIfTrue(buffer.size_bytes() < 2, "buffer too small");
    buffer = buffer.subspan(2);

    uint16_t size{0};
    for (auto&& p : protocols_)
    {
        ThrowIfTrue(p.length() >= 256, "ALPN name too long");
        if (!p.empty())
        {
            size += append_length_and_value(buffer, p.data(), p.size(), 1);
        }
    }

    buffer[0] = utils::get_byte<0>(size);
    buffer[1] = utils::get_byte<1>(size);
    size += 2;
    return size;
}

bool ALPN::empty() const
{
    return protocols_.empty();
}

const std::vector<std::string>& ALPN::protocols() const
{
    return protocols_;
}

std::string ALPN::singleProtocol() const
{
    return protocols_.front();
}

} // namespace snet::tls