#pragma once
#include <string>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/bio.hpp>

namespace snet::crypto
{

class CertName final
{
public:
    static X509NamePtr deepCopy(OSSL_CONST_COMPAT X509Name* name);

    static bool isEqual(const X509Name* a, const X509Name* b);

    static std::string serialNumber(OSSL_CONST_COMPAT X509Name* name);

    static inline std::string toString(const X509Name* name)
    {
        auto bio = BioTraits::createMemoryBuffer();
        X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);
        return BioTraits::getMemoryDataAsString(bio);
    }
};

} // namespace snet::crypto
