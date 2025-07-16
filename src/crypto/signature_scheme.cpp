#include <openssl/evp.h>

#include <snet/crypto/signature.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/crypto_manager.hpp>

#include <casket/utils/contains.hpp>

namespace snet::crypto
{

bool SignatureScheme::isSet() const noexcept
{
    return code_ != NONE;
}

std::string_view SignatureScheme::toString() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_MD5:
        return "RSA_PKCS1_MD5";
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

    case DSA_MD5:
        return "DSA_MD5";
    case DSA_SHA1:
        return "DSA_SHA1";
    case DSA_SHA224:
        return "DSA_SHA256";
    case DSA_SHA384:
        return "DSA_SHA384";
    case DSA_SHA512:
        return "DSA_SHA512";

    case ECDSA_MD5:
        return "ECDSA_MD5";
    case ECDSA_SHA1:
        return "ECDSA_SHA1";
    case ECDSA_SHA224:
        return "ECDSA_SHA256";
    case ECDSA_SHA384:
        return "ECDSA_SHA384";
    case ECDSA_SHA512:
        return "ECDSA_SHA512";

    case RSA_PSS_RSAE_SHA256:
        return "RSA_PSS_RSAE_SHA256";
    case RSA_PSS_RSAE_SHA384:
        return "RSA_PSS_RSAE_SHA384";
    case RSA_PSS_RSAE_SHA512:
        return "RSA_PSS_RSAE_SHA512";

    case EDDSA_25519:
        return "EDDSA_25519";
    case EDDSA_448:
        return "EDDSA_448";

    case RSA_PSS_PSS_SHA256:
        return "RSA_PSS_SHA256";
    case RSA_PSS_PSS_SHA384:
        return "RSA_PSS_SHA384";
    case RSA_PSS_PSS_SHA512:
        return "RSA_PSS_SHA512";

    default:
        return "UKNOWN";
    }
}

std::string_view SignatureScheme::getHashAlgorithm() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_MD5:
    case DSA_MD5:
    case ECDSA_MD5:
        return SN_md5;

    case RSA_PKCS1_SHA1:
    case DSA_SHA1:
    case ECDSA_SHA1:
        return SN_sha1;

    case RSA_PKCS1_SHA224:
    case DSA_SHA224:
    case ECDSA_SHA224:
        return SN_sha224;

    case RSA_PKCS1_SHA256:
    case DSA_SHA256:
    case ECDSA_SHA256:
    case RSA_PSS_RSAE_SHA256:
    case RSA_PSS_PSS_SHA256:
        return SN_sha256;

    case RSA_PKCS1_SHA384:
    case DSA_SHA384:
    case ECDSA_SHA384:
    case RSA_PSS_RSAE_SHA384:
    case RSA_PSS_PSS_SHA384:
        return SN_sha384;

    case RSA_PKCS1_SHA512:
    case DSA_SHA512:
    case ECDSA_SHA512:
    case RSA_PSS_RSAE_SHA512:
    case RSA_PSS_PSS_SHA512:
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
    case RSA_PKCS1_MD5:
    case RSA_PKCS1_SHA1:
    case RSA_PKCS1_SHA256:
    case RSA_PKCS1_SHA384:
    case RSA_PKCS1_SHA512:
        return EVP_PKEY_RSA;

    case DSA_MD5:
    case DSA_SHA1:
    case DSA_SHA224:
    case DSA_SHA256:
    case DSA_SHA384:
    case DSA_SHA512:
        return EVP_PKEY_DSA;

    case ECDSA_MD5:
    case ECDSA_SHA1:
    case ECDSA_SHA224:
    case ECDSA_SHA256:
    case ECDSA_SHA384:
    case ECDSA_SHA512:
        return EVP_PKEY_EC;

    case RSA_PSS_PSS_SHA256:
    case RSA_PSS_PSS_SHA384:
    case RSA_PSS_PSS_SHA512:
    case RSA_PSS_RSAE_SHA256:
    case RSA_PSS_RSAE_SHA384:
    case RSA_PSS_RSAE_SHA512:
        return EVP_PKEY_RSA_PSS;

    case EDDSA_25519:
        return EVP_PKEY_ED25519;

    case EDDSA_448:
        return EVP_PKEY_ED448;

    default:
        return NID_undef;
    }
}

} // namespace snet::tls