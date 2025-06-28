#include <snet/cpp_port/span.hpp>
#include <openssl/x509.h>
#include <snet/crypto/cert_name.hpp>

namespace snet::crypto::name {

bool isEqual(const CertName* op1, const CertName* op2) {
    return 0 == X509_NAME_cmp(op1, op2);
}

static cpp::span<uint8_t> viewEntryValue(const CertName* name, const int nid) {
    auto loc = X509_NAME_get_index_by_NID(name, nid, -1);
    if (loc >= 0) {
        auto entry = X509_NAME_get_entry(name, loc);
        if (entry) {
            auto value = X509_NAME_ENTRY_get_data(entry);
            return cpp::span(value->data, value->length);
        }
    }
    return cpp::span<uint8_t>();
}

std::string serialNumber(const CertName* name) {
    auto entry = viewEntryValue(name, NID_serialNumber);
    if (entry.empty())
        return std::string();
    return std::string(reinterpret_cast<char*>(entry.data()), entry.size_bytes());
}

} // namespace snet::crypto::name