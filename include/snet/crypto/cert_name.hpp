#pragma once
#include <string>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class CertName final
{
public:
    static X509NamePtr deepCopy(const X509Name* name);

    static bool isEqual(const X509Name* a, const X509Name* b);

    static std::string serialNumber(const X509Name* name);
};

} // namespace snet::crypto