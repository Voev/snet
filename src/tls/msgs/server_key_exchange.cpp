#include <snet/tls/msgs/server_key_exchange.hpp>

#include <snet/utils/data_reader.hpp>

using namespace snet::crypto;

namespace snet::tls
{

void DhParams::deserialize(utils::DataReader& reader)
{
    prime = reader.get_span<uint8_t>(2, 1, 65535);
    generator = reader.get_span<uint8_t>(2, 1, 65535);
    publicValue = reader.get_span<uint8_t>(2, 1, 65535);
}

void EcdheParams::deserialize(utils::DataReader& reader)
{
    curveType = reader.get_byte();

    curveID = GroupParams(reader.get_uint16_t());
    casket::ThrowIfFalse(curveID.isPureEccGroup(), "Invalid curve ID");

    publicPoint = reader.get_span<uint8_t>(1, 1, 255);
}

void ServerKeyExchange::deserialize(nonstd::span<const uint8_t> input, const int kex, const int auth,
                                    const ProtocolVersion& version)
{
    utils::DataReader reader("ServerKeyExchange", input.subspan(TLS_HANDSHAKE_HEADER_SIZE));

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

    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (version == ProtocolVersion::TLSv1_2)
        {
            scheme = SignatureScheme(reader.get_uint16_t());   // algorithm
            signature = reader.get_span<uint8_t>(2, 0, 65535); // signature
        }
        else /// < TLSv1.2
        {
            signature = reader.get_span<uint8_t>(2, 0, 65535); // signature
        }
    }

    reader.assert_done();
}

} // namespace snet::tls