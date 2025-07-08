#include <openssl/evp.h>

#include <snet/crypto/signature.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/crypto_manager.hpp>

#include <casket/utils/contains.hpp>

namespace snet::crypto
{

const std::vector<SignatureScheme>& SignatureScheme::availableSchemes()
{
    static const std::vector<SignatureScheme> allSchemes = {
        /* Legacy algorithms */
        RSA_PKCS1_SHA1,
        ECDSA_SHA1,

        /* RSASSA-PKCS1-v1_5 algorithms */
        RSA_PKCS1_SHA224,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        RSA_PSS_RSAE_SHA256,
        RSA_PSS_RSAE_SHA384,
        RSA_PSS_RSAE_SHA512,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        RSA_PSS_PSS_SHA256,
        RSA_PSS_PSS_SHA384,
        RSA_PSS_PSS_SHA512,

        /* ECDSA algorithms */
        ECDSA_SECP224R1_SHA224,
        ECDSA_SECP256R1_SHA256,
        ECDSA_SECP384R1_SHA384,
        ECDSA_SECP521R1_SHA512,

        /* EdDSA algorithms */
        EDDSA_25519,
        EDDSA_448,
    };

    return allSchemes;
}

bool SignatureScheme::isAvailable() const noexcept
{
    return casket::contains(SignatureScheme::availableSchemes(), *this);
}

bool SignatureScheme::isSet() const noexcept
{
    return code_ != NONE;
}

std::string_view SignatureScheme::toString() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
        return "RSA_PKCS1_SHA1";
    case RSA_PKCS1_SHA224:
        return "RSA_PKCS1_SHA224";
    case RSA_PKCS1_SHA256:
        return "RSA_PKCS1_SHA256";
    case RSA_PKCS1_SHA384:
        return "RSA_PKCS1_SHA384";
    case RSA_PKCS1_SHA512:
        return "RSA_PKCS1_SHA512";

    case RSA_PSS_RSAE_SHA256:
        return "RSA_PSS_RSAE_SHA256";
    case RSA_PSS_RSAE_SHA384:
        return "RSA_PSS_RSAE_SHA384";
    case RSA_PSS_RSAE_SHA512:
        return "RSA_PSS_RSAE_SHA512";

    case RSA_PSS_PSS_SHA256:
        return "RSA_PSS_SHA256";
    case RSA_PSS_PSS_SHA384:
        return "RSA_PSS_SHA384";
    case RSA_PSS_PSS_SHA512:
        return "RSA_PSS_SHA512";

    case ECDSA_SHA1:
        return "ECDSA_SHA1";
    case ECDSA_SECP224R1_SHA224:
        return "ECDSA_SHA256";
    case ECDSA_SECP384R1_SHA384:
        return "ECDSA_SHA384";
    case ECDSA_SECP521R1_SHA512:
        return "ECDSA_SHA512";

    case EDDSA_25519:
        return "EDDSA_25519";
    case EDDSA_448:
        return "EDDSA_448";

    default:
        return "UKNOWN";
    }
}

std::string_view SignatureScheme::getHashAlgorithm() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
    case ECDSA_SHA1:
        return SN_sha1;

    case RSA_PKCS1_SHA224:
    case ECDSA_SECP224R1_SHA224:
        return SN_sha224;

    case RSA_PKCS1_SHA256:
    case RSA_PSS_RSAE_SHA256:
    case RSA_PSS_PSS_SHA256:
    case ECDSA_SECP256R1_SHA256:
        return SN_sha256;

    case RSA_PKCS1_SHA384:
    case RSA_PSS_RSAE_SHA384:
    case RSA_PSS_PSS_SHA384:
    case ECDSA_SECP384R1_SHA384:
        return SN_sha384;

    case RSA_PKCS1_SHA512:
    case RSA_PSS_RSAE_SHA512:
    case RSA_PSS_PSS_SHA512:
    case ECDSA_SECP521R1_SHA512:
        return SN_sha512;

    case EDDSA_25519:
    case EDDSA_448:
        break;
    default:
        break;
    }
    return SN_undef;
}

int SignatureScheme::getKeyAlgorithm() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
    case RSA_PKCS1_SHA256:
    case RSA_PKCS1_SHA384:
    case RSA_PKCS1_SHA512:

        return EVP_PKEY_RSA;

    case RSA_PSS_PSS_SHA256:
    case RSA_PSS_PSS_SHA384:
    case RSA_PSS_PSS_SHA512:

    case RSA_PSS_RSAE_SHA256:
    case RSA_PSS_RSAE_SHA384:
    case RSA_PSS_RSAE_SHA512:

        return EVP_PKEY_RSA_PSS;

    case ECDSA_SHA1:
    case ECDSA_SECP224R1_SHA224:
    case ECDSA_SECP256R1_SHA256:
    case ECDSA_SECP384R1_SHA384:
    case ECDSA_SECP521R1_SHA512:

        return EVP_PKEY_EC;

    case EDDSA_25519:
        return EVP_PKEY_ED25519;

    case EDDSA_448:
        return EVP_PKEY_ED448;

        /// case DSA:
        /// @todo: support?
        /// return EVP_PKEY_DSA;

    default:
        return NID_undef;
    }
}

} // namespace snet::tls