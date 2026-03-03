#include <snet/tls/msgs/client_key_exchange.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

using namespace snet::crypto;

namespace snet::tls
{

void EncryptedPreMasterSecret::deserialize(utils::DataReader& reader)
{
    preMasterSecret = reader.get_span(2, 1, 65535);
}

size_t EncryptedPreMasterSecret::serialize(nonstd::span<uint8_t> output) const
{
    return append_length_and_value(output, preMasterSecret.data(), preMasterSecret.size(), 2);
}

void ClientDhPublic::deserialize(utils::DataReader& reader)
{
    dhPublic = reader.get_span(2, 1, 65535);
}

size_t ClientDhPublic::serialize(nonstd::span<uint8_t> output) const
{
    return append_length_and_value(output, dhPublic.data(), dhPublic.size(), 2);
}

void ClientEcdhPublic::deserialize(utils::DataReader& reader)
{
    ecdhPublic = reader.get_span(1, 1, 255);
}

size_t ClientEcdhPublic::serialize(nonstd::span<uint8_t> output) const
{
    return append_length_and_value(output, ecdhPublic.data(), ecdhPublic.size(), 1);
}

void ClientKeyExchange::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    utils::DataReader reader("ClientKeyExchange", input);

    casket::ThrowIfFalse(metaInfo.cipherSuite, "Cipher suite not setted");

    auto kex = CipherSuiteGetKeyExchange(metaInfo.cipherSuite);
    if (kex == NID_kx_rsa)
    {
        params.emplace<EncryptedPreMasterSecret>().deserialize(reader);
    }
    else if (kex == NID_kx_dhe || kex == NID_kx_dhe_psk)
    {
        params.emplace<ClientDhPublic>().deserialize(reader);
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        params.emplace<ClientEcdhPublic>().deserialize(reader);
    }
    else
    {
        throw std::runtime_error("ClientKeyExchange: Unsupported kex type");
    }
    reader.assert_done();
}

ClientKeyExchange ClientKeyExchange::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    ClientKeyExchange keyExchange;
    keyExchange.parse(input, metaInfo);
    return keyExchange;
}

size_t ClientKeyExchange::serialize(nonstd::span<uint8_t> output, const Session&) const
{
    return std::visit([&](const auto& inner) -> size_t { return inner.serialize(output); }, params);
}

} // namespace snet::tls