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

/// @brief Represents Diffie-Hellman parameters in Server Key Exchange.
///
/// Contains the DH parameters sent by the server during key exchange,
/// including prime modulus, generator, and server's public value.
struct DhParams final
{
    /// @brief Deserialize DH parameters from a data reader.
    ///
    /// @param[in] reader Data reader containing the serialized parameters.
    void deserialize(utils::DataReader& reader);

    /// @brief Serialize DH parameters to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized parameters to.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output);

    nonstd::span<const uint8_t> prime;       ///< DH prime modulus (p).
    nonstd::span<const uint8_t> generator;   ///< DH generator (g).
    nonstd::span<const uint8_t> publicValue; ///< Server's DH public value (g^x mod p).
};

/// @brief Represents Elliptic Curve Diffie-Hellman parameters in Server Key Exchange.
///
/// Contains the ECDH parameters sent by the server during key exchange,
/// including curve type, curve identifier, and server's public point.
struct EcdheParams final
{
    /// @brief Deserialize ECDH parameters from a data reader.
    ///
    /// @param[in] reader Data reader containing the serialized parameters.
    void deserialize(utils::DataReader& reader);

    /// @brief Serialize ECDH parameters to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized parameters to.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output);

    uint8_t curveType{0};                    ///< Type of curve (explicit or named curve).
    crypto::GroupParams curveID;             ///< Named curve identifier for standard curves.
    nonstd::span<const uint8_t> publicPoint; ///< Server's ECDH public point.
};

/// @brief Represents a Server Key Exchange message in TLS protocol.
///
/// This structure handles the key exchange parameters sent by the server
/// during the TLS handshake for algorithms that require additional parameters
/// (DHE and ECDHE cipher suites). It includes the key exchange parameters
/// and their signature for authentication.
struct ServerKeyExchange final
{
    /// @brief Variant type representing different key exchange parameters.
    using Params = std::variant<DhParams, EcdheParams>;

    /// @brief Parse a Server Key Exchange message from raw data.
    ///
    /// @param[in] input Raw bytes containing the Server Key Exchange message.
    /// @param[in] metaInfo Metadata information for parsing context.
    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Static factory method to deserialize a Server Key Exchange message.
    ///
    /// @param[in] input Raw bytes containing the Server Key Exchange message.
    /// @param[in] metaInfo Metadata information for parsing context.
    ///
    /// @return Parsed ServerKeyExchange object.
    static ServerKeyExchange deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Serialize the Server Key Exchange message to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    /// @param[in] session Session context for serialization.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session);

    Params params;                         ///< Key exchange parameters (DH or ECDH).
    nonstd::span<const uint8_t> data;      ///< Raw data containing parameters to be signed.
    crypto::SignatureScheme scheme;        ///< Signature scheme used to sign the parameters.
    nonstd::span<const uint8_t> signature; ///< Signature over the parameters for authentication.
};

} // namespace snet::tls