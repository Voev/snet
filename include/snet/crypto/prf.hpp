/// @file
/// @brief Pseudo-Random Functions (PRF) and key-derivation helpers for TLS/SSL.

#pragma once
#include <cstdint>
#include <vector>
#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>

namespace snet::crypto
{

constexpr size_t kSsl3Md5Len = 16;                               ///< SSL 3.0 Finished: MD5 part length.
constexpr size_t kSsl3Sha1Len = 20;                              ///< SSL 3.0 Finished: SHA-1 part length.
constexpr size_t kSsl3FinishedSize = kSsl3Md5Len + kSsl3Sha1Len; ///< SSL 3.0 Finished verify_data size (36).

/// @brief SSL 3.0 Pseudo-Random Function (RFC 6101, 6.3).
///
/// Expands @p secret into @p out using MD5/SHA-1 with salt seeds 'A', 'BB', 'CCC', ...
///
/// @param[in]  secret        Secret key (PMS or master secret).
/// @param[in]  clientRandom  ClientHello.random (32 bytes).
/// @param[in]  serverRandom  ServerHello.random (32 bytes).
/// @param[out] out           Output buffer; its length determines the expansion size.
///
void ssl3Prf(nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> clientRandom,
             nonstd::span<const uint8_t> serverRandom, nonstd::span<uint8_t> out);

/// @brief Computes the SSL 3.0 Finished MAC (RFC 6101, 5.6.9).
///
/// Concatenates two double-hashed digests:
///   MD5(master || pad2_md5  || MD5(handshake || sender || master || pad1_md5))
///   SHA1(master || pad2_sha1 || SHA1(handshake || sender || master || pad1_sha1))
/// where pad1 = 0x36 x {48|40}, pad2 = 0x5C x {48|40} (MD5|SHA-1).
///
/// @param[in]  masterSecret  48-byte master secret.
/// @param[in]  handshake     All handshake messages up to (excluding) this Finished,
///                           each with its 4-byte handshake header.
/// @param[in]  sideIndex     0 = client (sender "CLNT"), 1 = server (sender "SRVR").
/// @param[out] out           Output buffer, at least 36 bytes (16 MD5 + 20 SHA-1).
/// @throw casket::RuntimeError on invalid sizes or OpenSSL failure.
/// @see RFC 6101, section 5.6.9
void ssl3FinishedMac(nonstd::span<const uint8_t> masterSecret, nonstd::span<const uint8_t> handshake,
                     std::int8_t sideIndex, nonstd::span<uint8_t> out);

/// @brief TLS 1.0/1.1/1.2 Pseudo-Random Function (RFC 2246, 5).
///
/// P_MD5 || P_SHA1 expansion over @p secret with @p label and randoms.
///
/// @param[in]  algorithm     Digest name (e.g. "MD5-SHA1", "SHA256").
/// @param[in]  secret        Secret key.
/// @param[in]  label         PRF label (e.g. "master secret", "key expansion").
/// @param[in]  clientRandom  ClientHello.random.
/// @param[in]  serverRandom  ServerHello.random.
/// @param[out] out           Output buffer; its length determines the expansion size.
///
void tls1Prf(nonstd::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::string_view label,
             nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out);

/// @brief TLS 1.3 HKDF-Extract + Derive-Secret (RFC 8446, 7.1).
///
/// Computes @c HKDF-Extract(prevSecret, inSecret) with the "derived" label when
/// @p prevSecret is non-empty, otherwise uses zeros.
///
/// @param[in]  hashAlg     Handshake digest.
/// @param[in]  prevSecret  Previous secret (may be empty → zeros).
/// @param[in]  inSecret    Input keying material (may be empty → zeros).
/// @param[out] outSecret   Output secret (hash-length bytes).
///
void GenerateSecret(const Hash* hashAlg, nonstd::span<const uint8_t> prevSecret, nonstd::span<const uint8_t> inSecret,
                    nonstd::span<uint8_t> outSecret);

/// @brief TLS 1.3 HKDF-Expand-Label (RFC 8446, 7.1).
///
/// @param[in]  algorithm  Digest name.
/// @param[in]  secret     Pseudo-random key.
/// @param[in]  label      Label (without "tls13 " prefix).
/// @param[in]  data       Context (may be empty).
/// @param[out] out        Output buffer; its length determines the expansion size.
///
void HkdfExpand(nonstd::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> label,
                nonstd::span<const uint8_t> data, nonstd::span<uint8_t> out);

/// @brief Derives the client handshake traffic secret ("c hs traffic").
///
/// @param[in]  hashAlg  Handshake digest.
/// @param[in]  secret   Handshake secret.
/// @param[in]  data     Transcript hash of ClientHello..ServerHello.
/// @param[out] out      Output secret (hash-length bytes).
///
void DeriveClientHsTraffic(const Hash* hashAlg, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> data,
                           nonstd::span<uint8_t> out);

/// @brief Derives the server handshake traffic secret ("s hs traffic").
///
/// @param[in]  hashAlg  Handshake digest.
/// @param[in]  secret   Handshake secret.
/// @param[in]  data     Transcript hash of ClientHello..ServerHello.
/// @param[out] out      Output secret (hash-length bytes).
///
void DeriveServerHsTraffic(const Hash* hashAlg, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> data,
                           nonstd::span<uint8_t> out);

/// @brief Derives the client application traffic secret ("c ap traffic").
///
/// @param[in]  hashAlg  Handshake digest.
/// @param[in]  secret   Master secret.
/// @param[in]  data     Transcript hash of ClientHello..server Finished.
/// @param[out] out      Output secret (hash-length bytes).
///
void DeriveClientApTraffic(const Hash* hashAlg, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> data,
                           nonstd::span<uint8_t> out);

/// @brief Derives the server application traffic secret ("s ap traffic").
///
/// @param[in]  hashAlg  Handshake digest.
/// @param[in]  secret   Master secret.
/// @param[in]  data     Transcript hash of ClientHello..server Finished.
/// @param[out] out      Output secret (hash-length bytes).
///
void DeriveServerApTraffic(const Hash* hashAlg, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> data,
                           nonstd::span<uint8_t> out);

/// @brief Derives the Finished key ("finished") from a traffic secret (RFC 8446, 4.4.4).
///
/// @param[in]  algorithm  Digest name.
/// @param[in]  secret     Traffic secret.
/// @param[out] out        Output key (hash-length bytes).
///
void DeriveFinishedKey(nonstd::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

/// @brief Derives a record-protection key ("key") from a traffic secret.
///
/// @param[in]  algorithm  Digest name.
/// @param[in]  secret     Traffic secret.
/// @param[out] out        Output key (cipher key length).
///
void DeriveKey(nonstd::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

/// @brief Derives a record-protection IV ("iv") from a traffic secret.
///
/// @param[in]  algorithm  Digest name.
/// @param[in]  secret     Traffic secret.
/// @param[out] out        Output IV (cipher IV length).
///
void DeriveIV(nonstd::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

/// @brief Advances a traffic secret in place ("traffic upd") for KeyUpdate (RFC 8446, 7.2).
///
/// @param[in]     algorithm  Digest name.
/// @param[in,out] secret     Traffic secret to advance in place.
///
void UpdateTrafficSecret(nonstd::string_view algorithm, nonstd::span<uint8_t> secret);

} // namespace snet::crypto