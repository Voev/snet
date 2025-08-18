#pragma once
#include <cstdint>
#include <vector>
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

    constexpr uint16_t wireCode() const
    {
        return static_cast<uint16_t>(code_);
    }

    constexpr bool isX25519() const
    {
        return code_ == GroupParams::Code::X25519;
    }

    constexpr bool isX448() const
    {
        return code_ == GroupParams::Code::X448;
    }

    constexpr bool isEcdhNamedCurve() const
    {
        return code_ == GroupParams::Code::SECP256R1 || code_ == GroupParams::Code::SECP384R1 ||
               code_ == GroupParams::Code::SECP521R1 || code_ == GroupParams::Code::BRAINPOOL256R1 ||
               code_ == GroupParams::Code::BRAINPOOL384R1 || code_ == GroupParams::Code::BRAINPOOL512R1;
    }

    constexpr bool isInFfdheRange() const
    {
        // See RFC 7919
        return wireCode() >= 256 && wireCode() < 512;
    }

    constexpr bool isDhNamedGroup() const
    {
        return code_ == GroupParams::Code::FFDHE_2048 || code_ == GroupParams::Code::FFDHE_3072 ||
               code_ == GroupParams::Code::FFDHE_4096 || code_ == GroupParams::Code::FFDHE_6144 ||
               code_ == GroupParams::Code::FFDHE_8192;
    }

    constexpr bool isPureEccGroup() const
    {
        return isX25519() || isX448() || isEcdhNamedCurve();
    }

    static const std::vector<GroupParams>& getSupported();

    static crypto::KeyPtr generateParams(const GroupParams groupParams);

    static crypto::KeyPtr generateKeyByParams(const GroupParams groupParams);

    static crypto::KeyPtr generateKeyByParams(Key* params);

    static std::vector<uint8_t> deriveSecret(Key* privateKey, Key* publicKey, bool isTLSv3);

private:
    Code code_;
};

} // namespace snet::tls