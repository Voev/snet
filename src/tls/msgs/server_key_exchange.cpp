#include <snet/tls/msgs/server_key_exchange.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

using namespace snet::crypto;

namespace snet::tls
{

void DhParams::deserialize(utils::DataReader& reader)
{
    prime = reader.get_span(2, 1, 65535);
    generator = reader.get_span(2, 1, 65535);
    publicValue = reader.get_span(2, 1, 65535);
}

size_t DhParams::serialize(nonstd::span<uint8_t> output)
{
    size_t offset = 0;
    offset += append_length_and_value(output.subspan(offset), prime.data(), prime.size(), 2);
    offset += append_length_and_value(output.subspan(offset), generator.data(), generator.size(), 2);
    offset += append_length_and_value(output.subspan(offset), publicValue.data(), publicValue.size(), 2);
    return offset;
}

void EcdheParams::deserialize(utils::DataReader& reader)
{
    curveType = reader.get_byte();

    curveID = GroupParams(reader.get_uint16_t());
    casket::ThrowIfFalse(curveID.isPureEccGroup(), "Invalid curve ID");

    publicPoint = reader.get_span(1, 1, 255);
}

size_t EcdheParams::serialize(nonstd::span<uint8_t> output)
{
    size_t offset = 0;

    output[offset++] = curveType;

    const uint16_t namedCurveID = curveID.wireCode();
    output[offset++] = casket::get_byte<0>(namedCurveID);
    output[offset++] = casket::get_byte<1>(namedCurveID);

    offset += append_length_and_value(output.subspan(offset), publicPoint.data(), publicPoint.size(), 1);

    return offset;
}

void ServerKeyExchange::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    utils::DataReader reader("ServerKeyExchange", input);

    auto kex = CipherSuiteGetKeyExchange(metaInfo.cipherSuite);

    if (kex == NID_kx_dhe)
    {
        auto& dhParams = params.emplace<DhParams>();
        dhParams.deserialize(reader);
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        auto& ecdheParams = params.emplace<EcdheParams>();
        ecdheParams.deserialize(reader);
    }
    else if (kex != NID_kx_psk)
    {
        throw std::runtime_error("ServerKeyExchange: Unsupported kex type");
    }

    data = {input.data(), input.data() + reader.read_so_far()};

    auto auth = CipherSuiteGetAuth(metaInfo.cipherSuite);
    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (metaInfo.version == ProtocolVersion::TLSv1_2)
        {
            scheme = SignatureScheme(reader.get_uint16_t()); // algorithm
            signature = reader.get_span(2, 0, 65535);        // signature
        }
        else /// < TLSv1.2
        {
            signature = reader.get_span(2, 0, 65535); // signature
        }
    }

    reader.assert_done();
}

ServerKeyExchange ServerKeyExchange::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    ServerKeyExchange keyExchange;
    keyExchange.parse(input, metaInfo);
    return keyExchange;
}

size_t ServerKeyExchange::serialize(nonstd::span<uint8_t> output, const Session& session)
{
    size_t offset = 0;
    const auto& metaInfo = session.getInfo();

    auto kex = CipherSuiteGetKeyExchange(metaInfo.cipherSuite);
    if (kex == NID_kx_dhe)
    {
        auto& dhParams = std::get<DhParams>(params);
        offset += dhParams.serialize(output.subspan(offset));
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        auto& ecdheParams = std::get<EcdheParams>(params);
        offset += ecdheParams.serialize(output.subspan(offset));
    }
    else if (kex != NID_kx_psk)
    {
        throw std::runtime_error("ServerKeyExchange::serialize: Unsupported kex type");
    }

    auto auth = CipherSuiteGetAuth(metaInfo.cipherSuite);
    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (metaInfo.version == ProtocolVersion::TLSv1_2)
        {
            uint16_t schemeCode = scheme.wireCode();
            output[offset++] = casket::get_byte<0>(schemeCode);
            output[offset++] = casket::get_byte<1>(schemeCode);

            offset += append_length_and_value(output.subspan(offset), signature.data(), signature.size(), 2);
        }
        else /// < TLSv1.2
        {
            offset += append_length_and_value(output.subspan(offset), signature.data(), signature.size(), 2);
        }
    }

    return offset;
}

} // namespace snet::tls