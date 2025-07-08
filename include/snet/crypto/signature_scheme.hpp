#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <snet/crypto/typedefs.hpp>
#include <casket/nonstd/span.hpp>

namespace snet::crypto
{

class SignatureScheme final
{
public:
    enum Code : uint16_t
    {
        NONE = 0x0000,

        /* Legacy algorithms */
        RSA_PKCS1_SHA1 = 0x0201,
        ECDSA_SHA1 = 0x0203,

        /* RSASSA-PKCS1-v1_5 algorithms */
        RSA_PKCS1_SHA224 = 0x0301,
        RSA_PKCS1_SHA256 = 0x0401,
        RSA_PKCS1_SHA384 = 0x0501,
        RSA_PKCS1_SHA512 = 0x0601,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        RSA_PSS_RSAE_SHA256 = 0x0804,
        RSA_PSS_RSAE_SHA384 = 0x0805,
        RSA_PSS_RSAE_SHA512 = 0x0806,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        RSA_PSS_PSS_SHA256 = 0x0809,
        RSA_PSS_PSS_SHA384 = 0x080a,
        RSA_PSS_PSS_SHA512 = 0x080b,

        /* ECDSA algorithms */
        ECDSA_SECP224R1_SHA224 = 0x0303,
        ECDSA_SECP256R1_SHA256 = 0x0403,
        ECDSA_SECP384R1_SHA384 = 0x0503,
        ECDSA_SECP521R1_SHA512 = 0x0603,

        /* EdDSA algorithms */
        EDDSA_25519 = 0x0807,
        EDDSA_448 = 0x0808,
    };

public:
    constexpr SignatureScheme()
        : code_(NONE)
    {
    }

    constexpr SignatureScheme(uint16_t wireCode)
        : SignatureScheme(static_cast<Code>(wireCode))
    {
    }

    constexpr SignatureScheme(Code wireCode)
        : code_(wireCode)
    {
    }

    Code wireCode() const noexcept
    {
        return code_;
    }

    inline bool operator==(const SignatureScheme& rhs) const noexcept
    {
        return code_ == rhs.code_;
    }

    inline bool operator!=(const SignatureScheme& rhs) const noexcept
    {
        return !(*this == rhs);
    }

    static const std::vector<SignatureScheme>& availableSchemes();

    bool isAvailable() const noexcept;

    bool isSet() const noexcept;

    std::string_view toString() const noexcept;

    std::string_view getHashAlgorithm() const noexcept;

    int getKeyAlgorithm() const noexcept;

private:
    Code code_;
};

} // namespace snet::tls
