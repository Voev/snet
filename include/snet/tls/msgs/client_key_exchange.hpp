#pragma once
#include <variant>
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/meta_info.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

#include <snet/utils/data_reader.hpp>


namespace snet::tls
{

class Session;

struct EncryptedPreMasterSecret final
{
    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output);

    nonstd::span<const uint8_t> preMasterSecret;
};

struct ClientDhPublic final
{
    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output);

    nonstd::span<const uint8_t> dhPublic;
};

struct ClientEcdhPublic final
{
    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output);

    nonstd::span<const uint8_t> ecdhPublic;
};

struct ClientKeyExchange final
{
    using Params = std::variant<EncryptedPreMasterSecret, ClientDhPublic, ClientEcdhPublic>;

    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static ClientKeyExchange deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;

    Params params;
};

} // namespace snet::tls