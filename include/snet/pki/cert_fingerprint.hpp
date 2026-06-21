#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <snet/crypto/cert.hpp>
#include <snet/utils/bytes_to_number.hpp>

namespace snet::pki
{

struct CertFingerprint
{
    uint64_t hash;

    CertFingerprint()
        : hash(0)
    {
    }

    CertFingerprint(uint64_t h1)
        : hash(h1)
    {
    }

    bool operator==(const CertFingerprint& other) const
    {
        return hash == other.hash;
    }

    bool operator!=(const CertFingerprint& other) const
    {
        return !(*this == other);
    }

    bool operator<(const CertFingerprint& other) const
    {
        return hash < other.hash;
    }

    bool operator>(const CertFingerprint& other) const
    {
        return hash > other.hash;
    }

    std::string toString() const
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(16) << hash;
        return ss.str();
    }

    static CertFingerprint fromString(const std::string& str)
    {
        if (str.empty())
        {
            return CertFingerprint();
        }

        try
        {
            size_t pos = 0;
            uint64_t value = std::stoull(str, &pos, 16);
            
            if (pos != str.length())
            {
                return CertFingerprint();
            }
            
            return CertFingerprint(value);
        }
        catch (const std::exception&)
        {
            return CertFingerprint();
        }
    }

};

class CertFingerprintGenerator
{
public:
    static CertFingerprint generate(const X509Cert* cert, const Hash* hash)
    {
        uint8_t digest[EVP_MAX_MD_SIZE] = {};
        uint32_t digestLength = 0;

        crypto::ThrowIfFalse(0 < X509_digest(cert, hash, digest, &digestLength));
        return BytesToNumber<uint64_t>(digest, digestLength);
    }
};

} // namespace snet::pki

namespace std
{
template <>
struct hash<snet::pki::CertFingerprint>
{
    size_t operator()(const snet::pki::CertFingerprint& fp) const noexcept
    {
        return static_cast<size_t>(fp.hash);
    }
};
} // namespace std