#pragma once

#include <snet/crypto/signature_scheme.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

/// @brief Resolves the hash algorithm that was used to produce (or must be
///        used to verify) a TLS handshake signature.
///
/// The rule depends on the TLS version and on whether the wire format
/// carried a `SignatureAndHashAlgorithm` field:
///
///   - TLS 1.2+ (and TLS 1.3 CertificateVerify): the field is present, and
///     the hash is taken from it. For Ed25519/Ed448 the hash is built into
///     the signature algorithm and `hash == nullptr` is returned, which is
///     what `EVP_DigestVerifyInit(md = NULL)` expects.
///
///   - TLS 1.0/1.1 + RSA: RFC 5246 §7.4.1.4.1 mandates `{md5+sha1, rsa}`,
///     i.e. `EVP_md5_sha1()`.
///
///   - TLS 1.0/1.1 + DSA/ECDSA: RFC 4492 §5.4 mandates SHA-1. We derive it
///     from the cipher suite's HMAC digest, which is `SHA1` for every such
///     suite; this doubles as a generic fallback.
///
/// @param[in] scheme     Signature scheme from the wire (may be `NONE`).
/// @param[in] metaInfo   TLS meta information.
/// @param[in] publicKey  Peer public key (used to pick the TLS 1.0/1.1 rule).
///
/// @return Hash algorithm, or `nullptr` for EdDSA.
crypto::HashAlg resolveSignatureHash(crypto::SignatureScheme scheme, const MetaInfo& metaInfo, const Key* publicKey);

} // namespace snet::tls