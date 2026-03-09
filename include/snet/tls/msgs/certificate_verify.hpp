#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>

#include <snet/utils/algorithm.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

class Session;

/// @brief Represents a Certificate Verify message in TLS protocol.
///
/// This structure handles the verification of certificates during the TLS handshake,
/// including parsing, serialization, and signature verification for both TLS 1.2 and 1.3.
struct CertificateVerify final
{
    /// @brief Parse a Certificate Verify message from raw data.
    ///
    /// @param[in] input Raw bytes containing the Certificate Verify message.
    /// @param[in] metaInfo Metadata information for parsing context.
    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Static factory method to deserialize a Certificate Verify message.
    ///
    /// @param[in] input Raw bytes containing the Certificate Verify message.
    /// @param[in] metaInfo Metadata information for parsing context.
    ///
    /// @return Parsed CertificateVerify object.
    static CertificateVerify deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @brief Serialize the Certificate Verify message to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to.
    /// @param[in] session Session context for serialization.
    ///
    /// @return Number of bytes written to output buffer.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;

    /// @brief Perform TLS 1.3 signature generation.
    ///
    /// @param[in] scheme Signature scheme to use.
    /// @param[in] sideIndex Side index (client/server) for context.
    /// @param[in] ctx Hash context for signature computation.
    /// @param[in] privateKey Private key for signing.
    /// @param[in] transcriptHash Handshake transcript hash.
    /// @param[in] signatureBuffer Buffer to store the generated signature.
    ///
    /// @return Span containing the generated signature.
    static nonstd::span<uint8_t> doTLSv13Sign(const crypto::SignatureScheme& scheme, const int8_t sideIndex,
                                              HashCtx* ctx, Key* privateKey, nonstd::span<const uint8_t> transcriptHash,
                                              nonstd::span<uint8_t> signatureBuffer);

    /// @brief Perform TLS 1.3 signature verification.
    ///
    /// @param[in] certVerify CertificateVerify object containing the signature to verify.
    /// @param[in] sideIndex Side index (client/server) for context.
    /// @param[in] ctx Hash context for signature verification.
    /// @param[in] publicKey Public key for verification.
    /// @param[in] transcriptHash Handshake transcript hash.
    static void doTLSv13Verify(const CertificateVerify& certVerify, const int8_t sideIndex, HashCtx* ctx,
                               Key* publicKey, nonstd::span<const uint8_t> transcriptHash);

    crypto::SignatureScheme scheme{0};     ///< Signature scheme used for the certificate verification.
    nonstd::span<const uint8_t> signature; ///< Raw signature data.
};

/// @brief Choose an appropriate signature scheme based on available options.
///
/// @param[in] key The key to check suitability against.
/// @param[in] allowedSchemes List of signature schemes supported locally.
/// @param[in] peerAllowedSchemes List of signature schemes supported by peer.
///
/// @return Selected SignatureScheme, or SignatureScheme::NONE if no suitable scheme found.
inline crypto::SignatureScheme ChooseSignatureScheme(const Key* key,
                                                     nonstd::span<const crypto::SignatureScheme> allowedSchemes,
                                                     nonstd::span<const crypto::SignatureScheme> peerAllowedSchemes)
{
    for (auto scheme : allowedSchemes)
    {
        if (scheme.isSuitableFor(key) && ValueExists(peerAllowedSchemes, scheme))
        {
            return scheme;
        }
    }

    return crypto::SignatureScheme::NONE;
}

} // namespace snet::tls