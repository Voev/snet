#include <snet/tls/msgs/client_key_exchange.hpp>

#include <snet/tls/session.hpp>

#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code EncryptedPreMasterSecret::deserialize(utils::DataReader& reader) noexcept
{
    preMasterSecret = reader.get_span_length_and_value(2);
    return reader.take_ec();
}

std::size_t EncryptedPreMasterSecret::serialize(nonstd::span<uint8_t> output) const noexcept
{
    return AppendLengthAndValue(output, preMasterSecret.data(), preMasterSecret.size(), 2);
}

std::error_code ClientDhPublic::deserialize(utils::DataReader& reader) noexcept
{
    dhPublic = reader.get_span_length_and_value(2);
    return reader.take_ec();
}

std::size_t ClientDhPublic::serialize(nonstd::span<uint8_t> output) const noexcept
{
    return AppendLengthAndValue(output, dhPublic.data(), dhPublic.size(), 2);
}

std::error_code ClientEcdhPublic::deserialize(utils::DataReader& reader) noexcept
{
    ecdhPublic = reader.get_span_length_and_value(1);
    return reader.take_ec();
}

std::size_t ClientEcdhPublic::serialize(nonstd::span<uint8_t> output) const noexcept
{
    return AppendLengthAndValue(output, ecdhPublic.data(), ecdhPublic.size(), 1);
}

std::error_code ClientKeyExchange::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    if (metaInfo.cipherSuite == 0)
        return make_error_code(DecodeError::LengthOutOfRange);

    auto kex = CipherSuiteGetKeyExchange(metaInfo.cipherSuite);

    DataReader reader(input);

    if (kex == NID_kx_rsa)
    {
        EncryptedPreMasterSecret msg;
        if (const auto err = msg.deserialize(reader); err)
            return err;
        params = std::move(msg);
    }
    else if (kex == NID_kx_dhe || kex == NID_kx_dhe_psk)
    {
        ClientDhPublic msg;
        if (const auto err = msg.deserialize(reader); err)
            return err;
        params = std::move(msg);
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        ClientEcdhPublic msg;
        if (const auto err = msg.deserialize(reader); err)
            return err;
        params = std::move(msg);
    }
    else
    {
        return make_error_code(DecodeError::LengthOutOfRange); // unsupported kex
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t ClientKeyExchange::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    (void)session;

    return nonstd::visit(
        [&](const auto& inner) noexcept -> std::size_t
        {
            return inner.serialize(output);
        },
        params);
}

} // namespace snet::tls