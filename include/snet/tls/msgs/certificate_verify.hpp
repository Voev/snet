#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/signature_scheme.hpp>
#include <snet/tls/meta_info.hpp>
#include <snet/utils/algorithm.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS CertificateVerify handshake message
///        (TLS 1.2: RFC 5246 §7.4.8; TLS 1.3: RFC 8446 §4.4.3).
///
/// Wire format (identical for TLS 1.2 and TLS 1.3):
///   `<2-byte SignatureScheme>` + `<2-byte signature length>` + `<signature bytes>`.
///
/// `signature` is a view into the input buffer passed to `deserialize`; the
/// caller must keep that buffer alive for the lifetime of the object.
struct CertificateVerify final
{
    crypto::SignatureScheme scheme{0};       ///< Signature scheme used for the certificate verification.
    nonstd::span<const uint8_t> signature{}; ///< Raw signature data (`<2-byte length>` + bytes).

    /// @brief Default constructor; `scheme == 0`, `signature` empty.
    CertificateVerify() noexcept = default;

    /// @brief Parses the CertificateVerify body into `*this`.
    /// @param[in] input Wire bytes of the CertificateVerify body (without
    ///                  the 4-byte handshake header).
    /// @param[in] metaInfo Metadata information for parsing context.
    ///
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. `signature` points into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `2 + 2 + signature.size()` bytes.
    /// @param[in] session Session context (unused).
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;

    /// @brief Performs TLS 1.3 signature generation.
    /// @param[in] scheme          Signature scheme.
    /// @param[in] sideIndex       Side index (client/server) for context.
    /// @param[in] ctx             Hash context.
    /// @param[in] privateKey      Private key.
    /// @param[in] transcriptHash  Handshake transcript hash.
    /// @param[out] signatureBuffer Buffer for the generated signature.
    /// @return View over the generated signature bytes (into @p signatureBuffer).
    /// @throws casket::RuntimeError on crypto failure.
    static nonstd::span<uint8_t> doTLSv13Sign(const crypto::SignatureScheme& scheme, std::int8_t sideIndex,
                                              HashCtx* ctx, Key* privateKey, nonstd::span<const uint8_t> transcriptHash,
                                              nonstd::span<uint8_t> signatureBuffer);

    /// @brief Performs TLS 1.3 signature verification.
    /// @param[in] certVerify     CertificateVerify containing the signature.
    /// @param[in] sideIndex      Side index (client/server) for context.
    /// @param[in] ctx            Hash context.
    /// @param[in] publicKey      Public key.
    /// @param[in] transcriptHash Handshake transcript hash.
    /// @throws casket::RuntimeError on verification failure.
    static void doTLSv13Verify(const CertificateVerify& certVerify, std::int8_t sideIndex, HashCtx* ctx, Key* publicKey,
                               nonstd::span<const uint8_t> transcriptHash);
};

/// @brief Chooses a signature scheme acceptable to both sides.
///
/// Iterates @p allowedSchemes in order and returns the first that is
/// suitable for @p key and present in @p peerAllowedSchemes.
///
/// @param[in] key                Key to check suitability against.
/// @param[in] allowedSchemes     Locally supported schemes (preference order).
/// @param[in] peerAllowedSchemes Peer-supported schemes.
/// @return Selected scheme, or `crypto::SignatureScheme::NONE` if none match.
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