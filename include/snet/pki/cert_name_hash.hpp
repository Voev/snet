#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <snet/crypto/cert.hpp>

namespace snet::pki
{

struct CertNameHash
{
    uint32_t hash;

    CertNameHash()
        : hash(0)
    {
    }
    explicit CertNameHash(uint32_t h)
        : hash(h)
    {
    }

    bool operator==(const CertNameHash& other) const
    {
        return hash == other.hash;
    }
    bool operator!=(const CertNameHash& other) const
    {
        return !(*this == other);
    }
    bool operator<(const CertNameHash& other) const
    {
        return hash < other.hash;
    }
    bool operator>(const CertNameHash& other) const
    {
        return hash > other.hash;
    }

    std::string toString() const
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << hash;
        return ss.str();
    }

    static CertNameHash fromString(const std::string& str)
    {
        if (str.empty())
            return CertNameHash();
        try
        {
            size_t pos = 0;
            uint64_t value = std::stoull(str, &pos, 16);
            return (pos == str.length()) ? CertNameHash(value) : CertNameHash();
        }
        catch (...)
        {
            return CertNameHash();
        }
    }
};

class CertNameHashGenerator
{
public:
    static CertNameHash fromName(X509Name* name)
    {
        return CertNameHash(static_cast<uint32_t>(X509_NAME_hash(name)));
    }

    static CertNameHash fromCert(X509Cert* cert)
    {
        return fromName(crypto::Cert::subjectName(cert));
    }
};

} // namespace snet::pki

namespace std
{
template <>
struct hash<snet::pki::CertNameHash>
{
    size_t operator()(const snet::pki::CertNameHash& fp) const noexcept
    {
        return static_cast<size_t>(fp.hash);
    }
};
} // namespace std