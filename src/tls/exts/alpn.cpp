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

bool ALPN::empty() const
{
    return protocols_.empty();
}

size_t ALPN::serialize(Side side, std::span<uint8_t> output) const
{
    (void)side;

    ThrowIfTrue(output.size_bytes() < 2, "buffer too small");
    auto buffer = output.subspan(2);
    uint16_t totalLength{0};

    for (auto&& p : protocols_)
    {
        ThrowIfTrue(p.length() >= 256, "ALPN name too long");
        if (!p.empty())
        {
            auto encodedLength = append_length_and_value(buffer, p.data(), p.size(), 1);
            buffer = buffer.subspan(encodedLength);
            totalLength += encodedLength;
        }
    }

    output[0] = utils::get_byte<0>(totalLength);
    output[1] = utils::get_byte<1>(totalLength);

    totalLength += 2;

    return totalLength;
}

ALPN::ALPN(std::string_view protocol)
    : protocols_(1, std::string(protocol))
{
}

ALPN::ALPN(const std::vector<std::string>& protocols)
    : protocols_(protocols)
{
}

ALPN::ALPN(Side side, std::span<const uint8_t> input)
{
    utils::DataReader reader("ALPN", input);

    const uint16_t nameBytes = reader.get_uint16_t();
    ThrowIfTrue(nameBytes != reader.remaining_bytes(), "bad encoding of ALPN extension, bad length field");

    while (reader.has_remaining())
    {
        const std::string p = reader.get_string(1, 0, 255);
        ThrowIfTrue(p.empty(), "empty ALPN protocol not allowed");
        protocols_.push_back(p);
    }

    reader.assert_done();

    // RFC 7301 3.1
    //    The "extension_data" field of the [...] extension is structured the
    //    same as described above for the client "extension_data", except that
    //    the "ProtocolNameList" MUST contain exactly one "ProtocolName".
    ThrowIfTrue(side == Side::Server && protocols_.size() != 1, "server sent {} protocols in ALPN extension response",
                protocols_.size());
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