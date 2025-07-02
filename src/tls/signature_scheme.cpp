#include <snet/tls/signature_scheme.hpp>
#include <casket/utils/contains.hpp>

namespace snet::tls
{

const std::vector<SignatureScheme>& SignatureScheme::all_available_schemes()
{
    /*
     * This is ordered in some approximate order of preference
     */
    static const std::vector<SignatureScheme> all_schemes = {

        // EdDSA 25519 is currently not supported as a signature scheme for certificates
        // certificate authentication.
        // See: https://github.com/randombit/botan/pull/2958#discussion_r851294715
        //
        // #if defined(BOTAN_HAS_ED25519)
        //       EDDSA_25519,
        // #endif

        RSA_PSS_SHA384,   RSA_PSS_SHA256,   RSA_PSS_SHA512,

        RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PKCS1_SHA256,

        ECDSA_SHA384,     ECDSA_SHA512,     ECDSA_SHA256,
    };

    return all_schemes;
}

SignatureScheme::SignatureScheme()
    : code_(NONE)
{
}

SignatureScheme::SignatureScheme(uint16_t wire_code)
    : SignatureScheme(SignatureScheme::Code(wire_code))
{
}

SignatureScheme::SignatureScheme(SignatureScheme::Code wire_code)
    : code_(wire_code)
{
}

bool SignatureScheme::is_available() const noexcept
{
    return casket::contains(SignatureScheme::all_available_schemes(), *this);
}

bool SignatureScheme::is_set() const noexcept
{
    return code_ != NONE;
}

std::string SignatureScheme::to_string() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
        return "RSA_PKCS1_SHA1";
    case RSA_PKCS1_SHA256:
        return "RSA_PKCS1_SHA256";
    case RSA_PKCS1_SHA384:
        return "RSA_PKCS1_SHA384";
    case RSA_PKCS1_SHA512:
        return "RSA_PKCS1_SHA512";

    case ECDSA_SHA1:
        return "ECDSA_SHA1";
    case ECDSA_SHA256:
        return "ECDSA_SHA256";
    case ECDSA_SHA384:
        return "ECDSA_SHA384";
    case ECDSA_SHA512:
        return "ECDSA_SHA512";

    case RSA_PSS_SHA256:
        return "RSA_PSS_SHA256";
    case RSA_PSS_SHA384:
        return "RSA_PSS_SHA384";
    case RSA_PSS_SHA512:
        return "RSA_PSS_SHA512";

    case EDDSA_25519:
        return "EDDSA_25519";
    case EDDSA_448:
        return "EDDSA_448";

    default:
        return "Unknown signature scheme: " + std::to_string(code_);
    }
}

std::string SignatureScheme::hash_function_name() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
    case ECDSA_SHA1:
        return "SHA-1";

    case ECDSA_SHA256:
    case RSA_PKCS1_SHA256:
    case RSA_PSS_SHA256:
        return "SHA-256";

    case ECDSA_SHA384:
    case RSA_PKCS1_SHA384:
    case RSA_PSS_SHA384:
        return "SHA-384";

    case ECDSA_SHA512:
    case RSA_PKCS1_SHA512:
    case RSA_PSS_SHA512:
        return "SHA-512";

    case EDDSA_25519:
    case EDDSA_448:
        return "Pure";

    default:
        return "Unknown hash function";
    }
}

std::string SignatureScheme::padding_string() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
        return "PKCS1v15(SHA-1)";
    case RSA_PKCS1_SHA256:
        return "PKCS1v15(SHA-256)";
    case RSA_PKCS1_SHA384:
        return "PKCS1v15(SHA-384)";
    case RSA_PKCS1_SHA512:
        return "PKCS1v15(SHA-512)";

    case ECDSA_SHA1:
        return "SHA-1";
    case ECDSA_SHA256:
        return "SHA-256";
    case ECDSA_SHA384:
        return "SHA-384";
    case ECDSA_SHA512:
        return "SHA-512";

    case RSA_PSS_SHA256:
        return "PSS(SHA-256,MGF1,32)";
    case RSA_PSS_SHA384:
        return "PSS(SHA-384,MGF1,48)";
    case RSA_PSS_SHA512:
        return "PSS(SHA-512,MGF1,64)";

    case EDDSA_25519:
        return "Pure";
    case EDDSA_448:
        return "Pure";

    default:
        return "Unknown padding";
    }
}

std::string SignatureScheme::algorithm_name() const noexcept
{
    switch (code_)
    {
    case RSA_PKCS1_SHA1:
    case RSA_PKCS1_SHA256:
    case RSA_PKCS1_SHA384:
    case RSA_PKCS1_SHA512:
    case RSA_PSS_SHA256:
    case RSA_PSS_SHA384:
    case RSA_PSS_SHA512:
        return "RSA";

    case ECDSA_SHA1:
    case ECDSA_SHA256:
    case ECDSA_SHA384:
    case ECDSA_SHA512:
        return "ECDSA";

    case EDDSA_25519:
        return "Ed25519";

    case EDDSA_448:
        return "Ed448";

    default:
        return "Unknown algorithm";
    }
}

bool SignatureScheme::isCompatibleWith(const ProtocolVersion& version) const noexcept
{
    // RFC 8446 4.4.3:
    //   The SHA-1 algorithm MUST NOT be used in any signatures of
    //   CertificateVerify messages.
    //
    // Note that Botan enforces that for TLS 1.2 as well.
    if (hash_function_name() == "SHA-1")
    {
        return false;
    }

    // RFC 8446 4.4.3:
    //   RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether
    //   RSASSA-PKCS1-v1_5 algorithms appear in "signature_algorithms".
    //
    // Note that this is enforced for TLS 1.3 and above only.
    if (version <= ProtocolVersion::TLSv1_2 && (code_ == RSA_PKCS1_SHA1 || code_ == RSA_PKCS1_SHA256 ||
                                                code_ == RSA_PKCS1_SHA384 || code_ == RSA_PKCS1_SHA512))
    {
        return false;
    }

    return true;
}

} // namespace snet::tls