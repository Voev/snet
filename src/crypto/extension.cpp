#include <snet/crypto/extension.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto::ext {

CertExtPtr create(const int nid, cpp::span<uint8_t> value, bool critical) {
    // We don't want to copy data unnecessarily.
    ASN1_OCTET_STRING octet{};
    octet.data = value.data();
    octet.length = static_cast<int>(value.size());

    CertExtPtr ext(X509_EXTENSION_create_by_NID(nullptr, nid, critical, &octet));
    crypto::ThrowIfFalse(ext != nullptr);

    return ext;
}

cpp::span<const uint8_t> view(CertExt* extension) {
    auto octet = X509_EXTENSION_get_data(extension);
    return octet ? cpp::span(octet->data, octet->length) : cpp::span<const uint8_t>();
}

} // namespace snet::crypto::ext