#include <snet/tls/msgs/server_key_exchange.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/asymm_key.hpp>

using namespace snet::crypto;

namespace snet::tls
{

static KeyPtr HandlePeerKeyECDHE(utils::DataReader& reader)
{
    auto curveType = reader.get_byte();                 // curve type
    auto curveID = GroupParams(reader.get_uint16_t());  // curve id
    auto peerKey = reader.get_span<uint8_t>(1, 1, 255); // public key

    /*
     * Check curve is named curve type and one of our preferences, if not
     * server has sent an invalid curve.
     */
    (void)curveType;

    auto key = GenerateGroupParams(curveID);
    SetEncodedPublicKey(key, peerKey);

    return key;
}

void ServerKeyExchange::deserialize(nonstd::span<const uint8_t> input, const int kex, const int auth,
                                    const ProtocolVersion& version)
{
    utils::DataReader reader("ServerKeyExchange", input.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    if (kex == NID_kx_dhe)
    {
        // 3 bigints, DH p, g, Y
        for (size_t i = 0; i != 3; ++i)
        {
            reader.get_range<uint8_t>(2, 1, 65535);
        }
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        serverPublicKey_ = HandlePeerKeyECDHE(reader);
    }
    else if (kex != NID_kx_psk)
    {
        throw std::runtime_error("Server_Key_Exchange: Unsupported kex type");
    }

    params_.assign(input.data(), input.data() + reader.read_so_far());

    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        if (version == ProtocolVersion::TLSv1_2)
        {
            scheme_ = SignatureScheme(reader.get_uint16_t());    // algorithm
            signature_ = reader.get_range<uint8_t>(2, 0, 65535); // signature
        }
        else /// < TLSv1.2
        {
            signature_ = reader.get_range<uint8_t>(2, 0, 65535); // signature
        }
    }

    reader.assert_done();
}

const std::vector<uint8_t>& ServerKeyExchange::getParams() const noexcept
{
    return params_;
}

const std::vector<uint8_t>& ServerKeyExchange::getSignature() const noexcept
{
    return signature_;
}

} // namespace snet::tls