#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <snet/crypto/typedefs.hpp>
#include <casket/nonstd/span.hpp>

namespace snet::crypto
{

/// https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1

class SignatureScheme final
{
public:
    enum Code : uint16_t
    {
        NONE = 0x0000,

        /* RSA based */
        RSA_PKCS1_MD5 = 0x0101,
        RSA_PKCS1_SHA1 = 0x0201,
        RSA_PKCS1_SHA224 = 0x0301,
        RSA_PKCS1_SHA256 = 0x0401,
        RSA_PKCS1_SHA384 = 0x0501,
        RSA_PKCS1_SHA512 = 0x0601,

        /* DSA based */
        DSA_MD5 = 0x0102,
        DSA_SHA1 = 0x0202,
        DSA_SHA224 = 0x0302,
        DSA_SHA256 = 0x0402,
        DSA_SHA384 = 0x0502,
        DSA_SHA512 = 0x0602,

        /* ECDSA algorithms */
        ECDSA_MD5 = 0x0103,
        ECDSA_SHA1 = 0x0203,
        ECDSA_SHA224 = 0x0303,
        ECDSA_SHA256 = 0x0403,
        ECDSA_SHA384 = 0x0503,
        ECDSA_SHA512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        RSA_PSS_RSAE_SHA256 = 0x0804,
        RSA_PSS_RSAE_SHA384 = 0x0805,
        RSA_PSS_RSAE_SHA512 = 0x0806,

        /* EdDSA algorithms */
        EDDSA_25519 = 0x0807,
        EDDSA_448 = 0x0808,
        
        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        RSA_PSS_PSS_SHA256 = 0x0809,
        RSA_PSS_PSS_SHA384 = 0x080a,
        RSA_PSS_PSS_SHA512 = 0x080b,
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

    bool isSet() const noexcept;

    std::string_view toString() const noexcept;

    std::string_view getHashAlgorithm() const noexcept;

    int getKeyAlgorithm() const noexcept;

private:
    Code code_;
};

} // namespace snet::tls
