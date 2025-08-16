#include <snet/crypto/extension.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

X509ExtPtr X509Extension::create(const int nid, nonstd::span<uint8_t> value, bool critical)
{
    // We don't want to copy data unnecessarily.
    ASN1_OCTET_STRING octet{};
    octet.data = value.data();
    octet.length = static_cast<int>(value.size());

    X509ExtPtr ext(X509_EXTENSION_create_by_NID(nullptr, nid, critical, &octet));
    crypto::ThrowIfFalse(ext != nullptr);

    return ext;
}

nonstd::span<const uint8_t> X509Extension::view(X509Ext* extension)
{
    auto octet = X509_EXTENSION_get_data(extension);
    return octet ? nonstd::span(octet->data, octet->length) : nonstd::span<const uint8_t>();
}

} // namespace snet::crypto