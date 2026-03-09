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

/// @brief Represents an encrypted pre-master secret in TLS key exchange.
///
/// Used in RSA key exchange to securely transmit the pre-master secret
/// from client to server, encrypted with the server's public key.
struct EncryptedPreMasterSecret final
{
    /// @brief Deserialize the encrypted pre-master secret from a data reader.
    ///
    /// @param[in] reader Data reader containing the serialized data.
    void deserialize(utils::DataReader& reader);

    /// @brief Serialize the encrypted pre-master secret to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> preMasterSecret; ///< Raw encrypted pre-master secret data.
};

/// @brief Represents a client's Diffie-Hellman public value.
///
/// Used in traditional DH key exchange to transmit the client's
/// public DH parameter to the server.
struct ClientDhPublic final
{
    /// @brief Deserialize the client DH public value from a data reader.
    ///
    /// @param[in] reader Data reader containing the serialized data.
    void deserialize(utils::DataReader& reader);

    /// @brief Serialize the client DH public value to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> dhPublic; ///< Raw DH public value data.
};

/// @brief Represents a client's Elliptic Curve Diffie-Hellman public value.
///
/// Used in ECDH key exchange to transmit the client's
/// elliptic curve public key to the server.
struct ClientEcdhPublic final
{
    /// @brief Deserialize the client ECDH public value from a data reader.
    ///
    /// @param[in] reader Data reader containing the serialized data.
    void deserialize(utils::DataReader& reader);

    /// @brief Serialize the client ECDH public value to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> ecdhPublic; ///< Raw ECDH public value data.
};

/// @brief Represents a Client Key Exchange message in TLS protocol.
///
/// This structure handles the key exchange parameters sent by the client
/// during the TLS handshake. It supports multiple key exchange methods
/// through a variant type (EncryptedPreMasterSecret, ClientDhPublic, ClientEcdhPublic).
struct ClientKeyExchange final
{
    /// @brief Variant type representing different key exchange parameters.
    using Params = std::variant<EncryptedPreMasterSecret, ClientDhPublic, ClientEcdhPublic>;

    /// @brief Parse a Client Key Exchange message from raw data.
    ///
    /// @param[in] input Raw bytes containing the Client Key Exchange message.
    /// @param[in] metaInfo Metadata information for parsing context.
    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Static factory method to deserialize a Client Key Exchange message.
    ///
    /// @param[in] input Raw bytes containing the Client Key Exchange message.
    /// @param[in] metaInfo Metadata information for parsing context.
    ///
    /// @return Parsed ClientKeyExchange object.
    static ClientKeyExchange deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Serialize the Client Key Exchange message to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    /// @param[in] session Session context for serialization.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;

    Params params; ///< Key exchange parameters specific to the negotiated method.
};

} // namespace snet::tls