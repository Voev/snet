#pragma once
#include <variant>
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

struct DhParams final
{
    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output);

    nonstd::span<const uint8_t> prime;
    nonstd::span<const uint8_t> generator;
    nonstd::span<const uint8_t> publicValue;
};

struct EcdheParams final
{
    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output);

    uint8_t curveType{0};
    crypto::GroupParams curveID;
    nonstd::span<const uint8_t> publicPoint;
};

struct ServerKeyExchange final
{
    using Params = std::variant<DhParams, EcdheParams>;

    void deserialize(nonstd::span<const uint8_t> input, const int kex, const int auth, const ProtocolVersion& version);

    size_t serialize(nonstd::span<uint8_t> output) const;

    Params params;
    nonstd::span<const uint8_t> data;
    crypto::SignatureScheme scheme;
    nonstd::span<const uint8_t> signature;
};

} // namespace snet::tls