#pragma once
#include <cstdint>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class GroupParams final
{
public:
    enum Code : uint16_t
    {
        NONE = 0,

        SECP256R1 = 23,
        SECP384R1 = 24,
        SECP521R1 = 25,

        BRAINPOOL256R1 = 26,
        BRAINPOOL384R1 = 27,
        BRAINPOOL512R1 = 28,

        X25519 = 29,
        X448 = 30,

        FFDHE_2048 = 256,
        FFDHE_3072 = 257,
        FFDHE_4096 = 258,
        FFDHE_6144 = 259,
        FFDHE_8192 = 260,
    };

    constexpr GroupParams()
        : code_(Code::NONE)
    {
    }

    constexpr GroupParams(GroupParams::Code code)
        : code_(code)
    {
    }

    constexpr GroupParams(uint16_t code)
        : code_(static_cast<GroupParams::Code>(code))
    {
    }

    const char* toString() const;

    constexpr bool operator==(GroupParams::Code code) const
    {
        return code_ == code;
    }

    constexpr bool operator==(GroupParams other) const
    {
        return code_ == other.code_;
    }

    constexpr bool operator<(GroupParams other) const
    {
        return code_ < other.code_;
    }

    constexpr GroupParams::Code code() const
    {
        return code_;
    }

    constexpr uint16_t wire_code() const
    {
        return static_cast<uint16_t>(code_);
    }

    constexpr bool is_x25519() const
    {
        return code_ == GroupParams::Code::X25519;
    }

    constexpr bool is_x448() const
    {
        return code_ == GroupParams::Code::X448;
    }

    constexpr bool is_ecdh_named_curve() const
    {
        return code_ == GroupParams::Code::SECP256R1 || code_ == GroupParams::Code::SECP384R1 ||
               code_ == GroupParams::Code::SECP521R1 || code_ == GroupParams::Code::BRAINPOOL256R1 ||
               code_ == GroupParams::Code::BRAINPOOL384R1 || code_ == GroupParams::Code::BRAINPOOL512R1;
    }

    constexpr bool is_in_ffdhe_range() const
    {
        // See RFC 7919
        return wire_code() >= 256 && wire_code() < 512;
    }

    constexpr bool is_dh_named_group() const
    {
        return code_ == GroupParams::Code::FFDHE_2048 || code_ == GroupParams::Code::FFDHE_3072 ||
               code_ == GroupParams::Code::FFDHE_4096 || code_ == GroupParams::Code::FFDHE_6144 ||
               code_ == GroupParams::Code::FFDHE_8192;
    }

    constexpr bool is_pure_ecc_group() const
    {
        return is_x25519() || is_x448() || is_ecdh_named_curve();
    }

private:
    Code code_;
};

crypto::KeyPtr GenerateKeyByGroupParams(const GroupParams groupParams);

crypto::KeyPtr GenerateGroupParams(const GroupParams groupParams);

} // namespace snet::tls