#pragma once
#include <vector>
#include <string>
#include <optional>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class SignatureScheme final
{
public:
    /**
     * Matches with wire encoding
     *
     * Note that this is intentionally left as a bare enum. It emulates the Botan 2
     * API where `SignatureScheme` was an enum class with associated free-standing
     * functions. Leaving it as a bare enum resembles the legacy user-facing API.
     */
    enum Code : uint16_t
    {
        NONE = 0x0000,

        RSA_PKCS1_SHA1 = 0x0201, // not implemented
        RSA_PKCS1_SHA256 = 0x0401,
        RSA_PKCS1_SHA384 = 0x0501,
        RSA_PKCS1_SHA512 = 0x0601,

        ECDSA_SHA1 = 0x0203, // not implemented
        ECDSA_SHA256 = 0x0403,
        ECDSA_SHA384 = 0x0503,
        ECDSA_SHA512 = 0x0603,

        RSA_PSS_SHA256 = 0x0804,
        RSA_PSS_SHA384 = 0x0805,
        RSA_PSS_SHA512 = 0x0806,

        EDDSA_25519 = 0x0807,
        EDDSA_448 = 0x0808,
    };

public:
    /**
     * @return all available signature schemes
     */
    static const std::vector<SignatureScheme>& all_available_schemes();

    /**
     * Construct an uninitialized / invalid scheme
     */
    SignatureScheme();

    SignatureScheme(uint16_t wire_code);

    SignatureScheme(SignatureScheme::Code wire_code);

    SignatureScheme::Code wire_code() const noexcept
    {
        return code_;
    }

    /**
     * @return true if support for this scheme is implemented in this Botan build
     */
    bool is_available() const noexcept;

    /**
     * @return true if the wire_code is set to any value other than `NONE`
     */
    bool is_set() const noexcept;

    std::string to_string() const noexcept;
    std::string hash_function_name() const noexcept;
    std::string padding_string() const noexcept;
    std::string algorithm_name() const noexcept;

    bool isCompatibleWith(const ProtocolVersion& protocol_version) const noexcept;
    //bool isSuitableFor(const Private_Key& private_key) const noexcept;

    bool operator==(const SignatureScheme& rhs) const
    {
        return code_ == rhs.code_;
    }

    bool operator!=(const SignatureScheme& rhs) const
    {
        return !(*this == rhs);
    }

private:
    SignatureScheme::Code code_;
};

} // namespace snet::tls
