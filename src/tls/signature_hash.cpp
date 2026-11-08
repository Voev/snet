#include <snet/tls/signature_hash.hpp>

#include <casket/utils/string.hpp>

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/tls/cipher_suite.hpp>

namespace snet::tls
{

namespace
{

bool isEdDSA(crypto::SignatureScheme scheme) noexcept
{
    return scheme == crypto::SignatureScheme::EDDSA_25519 || scheme == crypto::SignatureScheme::EDDSA_448;
}

} // namespace

crypto::HashAlg resolveSignatureHash(crypto::SignatureScheme scheme, const MetaInfo& metaInfo, const Key* publicKey)
{
    // TLS 1.2+ / TLS 1.3 CertificateVerify: explicit SignatureAndHashAlgorithm.
    if (scheme.isSet())
    {
        // Ed25519/Ed448: hash is built into the scheme; md = NULL for OpenSSL.
        if (isEdDSA(scheme))
        {
            return nullptr;
        }
        return crypto::CryptoManager::getInstance().fetchDigest(scheme.getHashAlgorithm());
    }

    // TLS 1.0/1.1: no explicit field; hash is implied by the key type.
    // Defensive: reaching here on TLS 1.2+ means a malformed record.
    if (metaInfo.version >= ProtocolVersion::TLSv1_2)
    {
        return nullptr;
    }

    if (crypto::AsymmKey::isAlgorithm(publicKey, "RSA"))
    {
        // RFC 5246 §7.4.1.4.1: RSA -> {md5+sha1, rsa}, PKCS#1 v1.5.
        return crypto::CryptoManager::getInstance().fetchDigest(SN_md5_sha1);
    }

    // RFC 4492 §5.4: DSA/ECDSA -> SHA-1. Use the cipher suite's HMAC digest
    // as a generic fallback; for TLS 1.0/1.1 DSA/ECDSA suites it is "SHA1".
    return crypto::CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(metaInfo.cipherSuite));
}

} // namespace snet::tls