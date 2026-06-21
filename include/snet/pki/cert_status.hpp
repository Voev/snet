#pragma once
#include <string>

namespace snet::pki
{

enum class CertStatus
{
    UNKNOWN = 0,
    VALID,
    EXPIRED,
    REVOKED,
};

inline std::string CertStatusToString(CertStatus status)
{
    switch (status)
    {
    case CertStatus::VALID:
        return "valid";
    case CertStatus::EXPIRED:
        return "expired";
    case CertStatus::REVOKED:
        return "revoked";
    default:
        return "unknown";
    }
}

inline CertStatus StringToCertStatus(const std::string& str)
{
    if (str == "valid")
        return CertStatus::VALID;
    if (str == "expired")
        return CertStatus::EXPIRED;
    if (str == "revoked")
        return CertStatus::REVOKED;
    return CertStatus::UNKNOWN;
}

} // namespace snet::pki