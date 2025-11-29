#include <casket/nonstd/span.hpp>
#include <openssl/x509.h>
#include <snet/crypto/cert_name.hpp>

namespace snet::crypto
{

X509NamePtr CertName::deepCopy(OSSL_CONST_COMPAT X509Name* name)
{
    return X509NamePtr{X509_NAME_dup(name)};
}

bool CertName::isEqual(const X509Name* a, const X509Name* b)
{
    return (0 == X509_NAME_cmp(a, b));
}

static nonstd::span<uint8_t> viewEntryValue(OSSL_CONST_COMPAT X509Name* name, const int nid)
{
    auto loc = X509_NAME_get_index_by_NID(name, nid, -1);
    if (loc >= 0)
    {
        auto entry = X509_NAME_get_entry(name, loc);
        if (entry)
        {
            auto value = X509_NAME_ENTRY_get_data(entry);
            return nonstd::span(value->data, value->length);
        }
    }
    return nonstd::span<uint8_t>();
}

std::string CertName::serialNumber(OSSL_CONST_COMPAT X509Name* name)
{
    auto entry = viewEntryValue(name, NID_serialNumber);
    if (entry.empty())
    {
        return std::string();
    }
    return std::string(reinterpret_cast<char*>(entry.data()), entry.size_bytes());
}

} // namespace snet::crypto