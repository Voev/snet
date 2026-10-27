#include <snet/tls/msgs/server_key_exchange.hpp>

#include <cstring>

#include <snet/tls/session.hpp>

#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code DhParams::deserialize(utils::DataReader& reader) noexcept
{
    prime = {};
    generator = {};
    publicValue = {};

    prime = reader.get_span(2, 1, 65535);
    if (!reader.ok())
        return reader.take_ec();

    generator = reader.get_span(2, 1, 65535);
    if (!reader.ok())
        return reader.take_ec();

    publicValue = reader.get_span(2, 1, 65535);
    return reader.take_ec();
}

std::size_t DhParams::serialize(nonstd::span<uint8_t> output) const noexcept
{
    std::size_t pos = 0;

    {
        const auto n = AppendLengthAndValue(output.subspan(pos), prime.data(), prime.size(), 2);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        pos += n;
    }
    {
        const auto n = AppendLengthAndValue(output.subspan(pos), generator.data(), generator.size(), 2);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        pos += n;
    }
    {
        const auto n = AppendLengthAndValue(output.subspan(pos), publicValue.data(), publicValue.size(), 2);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        pos += n;
    }

    return pos;
}

std::error_code EcdheParams::deserialize(utils::DataReader& reader) noexcept
{
    curveType = 0;
    curveID = {};
    publicPoint = {};

    curveType = reader.get_byte();
    if (!reader.ok())
        return reader.take_ec();

    curveID = crypto::GroupParams(reader.get_uint16_t());
    if (!reader.ok())
        return reader.take_ec();
    if (!curveID.isPureEccGroup())
        return make_error_code(DecodeError::LengthOutOfRange);

    publicPoint = reader.get_span(1, 1, 255);
    return reader.take_ec();
}

std::size_t EcdheParams::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (output.size_bytes() < 3)
        return kSerializationFailed;

    std::size_t pos = 0;
    output[pos++] = curveType;

    const auto namedCurveID = static_cast<std::uint16_t>(curveID.wireCode());
    output[pos++] = casket::get_byte<0>(namedCurveID);
    output[pos++] = casket::get_byte<1>(namedCurveID);

    const auto n = AppendLengthAndValue(output.subspan(pos), publicPoint.data(), publicPoint.size(), 1);
    if (n == kSerializationFailed)
        return kSerializationFailed;
    return pos + n;
}

std::error_code ServerKeyExchange::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    if (metaInfo.cipherSuite == 0)
        return make_error_code(DecodeError::LengthOutOfRange);

    const auto kex = CipherSuiteGetKeyExchange(metaInfo.cipherSuite);

    DataReader reader(input);

    if (kex == NID_kx_dhe)
    {
        DhParams msg;
        if (const auto err = msg.deserialize(reader); err)
            return err;
        params = std::move(msg);
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        EcdheParams msg;
        if (const auto err = msg.deserialize(reader); err)
            return err;
        params = std::move(msg);
    }
    else if (kex != NID_kx_psk)
    {
        return make_error_code(DecodeError::LengthOutOfRange); // unsupported kex
    }

    data = {input.data(), input.data() + reader.read_so_far()};

    const auto auth = CipherSuiteGetAuth(metaInfo.cipherSuite);
    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (metaInfo.version == ProtocolVersion::TLSv1_2)
        {
            scheme = crypto::SignatureScheme(reader.get_uint16_t());
            if (!reader.ok())
                return reader.take_ec();
        }
        signature = reader.get_span(2, 0, 65535);
        if (!reader.ok())
            return reader.take_ec();
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t ServerKeyExchange::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    const auto& metaInfo = session.getInfo();
    std::size_t pos = 0;

    if (output.size_bytes() < data.size())
        return kSerializationFailed;
    if (!data.empty())
        std::memcpy(output.data(), data.data(), data.size());
    pos += data.size();

    const auto auth = CipherSuiteGetAuth(metaInfo.cipherSuite);
    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (metaInfo.version == ProtocolVersion::TLSv1_2)
        {
            const auto schemeCode = static_cast<std::uint16_t>(scheme.wireCode());
            output[pos++] = casket::get_byte<0>(schemeCode);
            output[pos++] = casket::get_byte<1>(schemeCode);
        }
        const auto n = AppendLengthAndValue(output.subspan(pos), signature.data(), signature.size(), 2);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        pos += n;
    }

    return pos;
}

} // namespace snet::tls