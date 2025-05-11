#pragma once
#include <cstdint>
#include <snet/crypto/pointers.hpp>

namespace snet::tls
{

enum class GroupParamsCode : uint16_t
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

class GroupParams final
{
public:
    using enum GroupParamsCode;

    constexpr GroupParams()
        : m_code(GroupParamsCode::NONE)
    {
    }

    constexpr GroupParams(GroupParamsCode code)
        : m_code(code)
    {
    }

    constexpr GroupParams(uint16_t code)
        : m_code(static_cast<GroupParamsCode>(code))
    {
    }

    const char* toString() const;
    /**
     * @returns std::nullopt if an unknown name
     */
    //    static std::optional<GroupParams> fromString(const char* group_name);

    constexpr bool operator==(GroupParamsCode code) const
    {
        return m_code == code;
    }

    constexpr bool operator==(GroupParams other) const
    {
        return m_code == other.m_code;
    }

    constexpr bool operator<(GroupParams other) const
    {
        return m_code < other.m_code;
    }

    constexpr GroupParamsCode code() const
    {
        return m_code;
    }

    constexpr uint16_t wire_code() const
    {
        return static_cast<uint16_t>(m_code);
    }

    constexpr bool is_x25519() const
    {
        return m_code == GroupParamsCode::X25519;
    }

    constexpr bool is_x448() const
    {
        return m_code == GroupParamsCode::X448;
    }

    constexpr bool is_ecdh_named_curve() const
    {
        return m_code == GroupParamsCode::SECP256R1 || m_code == GroupParamsCode::SECP384R1 ||
               m_code == GroupParamsCode::SECP521R1 || m_code == GroupParamsCode::BRAINPOOL256R1 ||
               m_code == GroupParamsCode::BRAINPOOL384R1 || m_code == GroupParamsCode::BRAINPOOL512R1;
    }

    constexpr bool is_in_ffdhe_range() const
    {
        // See RFC 7919
        return wire_code() >= 256 && wire_code() < 512;
    }

    constexpr bool is_dh_named_group() const
    {
        return m_code == GroupParamsCode::FFDHE_2048 || m_code == GroupParamsCode::FFDHE_3072 ||
               m_code == GroupParamsCode::FFDHE_4096 || m_code == GroupParamsCode::FFDHE_6144 ||
               m_code == GroupParamsCode::FFDHE_8192;
    }

    constexpr bool is_pure_ecc_group() const
    {
        return is_x25519() || is_x448() || is_ecdh_named_curve();
    }

private:
    GroupParamsCode m_code;
};

crypto::KeyPtr GenerateKeyByGroupParams(const GroupParams groupParams);

crypto::KeyPtr GenerateGroupParams(const GroupParams groupParams);

} // namespace snet::tls