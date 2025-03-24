#include <snet/tls/key.hpp>
#include <snet/crypto/exception.hpp>
#include <limits>

namespace snet::tls
{

EvpPkeyPtr LoadPrivateKey(const std::string& uri, const UI_METHOD* meth, void* data)
{
    StoreCtxPtr ctx(OSSL_STORE_open_ex(uri.c_str(), nullptr, nullptr, meth, data,
                                       nullptr, nullptr, nullptr));
    crypto::ThrowIfFalse(ctx != nullptr);

    crypto::ThrowIfFalse(0 < OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY));

    StoreInfoPtr info(OSSL_STORE_load(ctx));
    crypto::ThrowIfFalse(info != nullptr);

    return EvpPkeyPtr{OSSL_STORE_INFO_get1_PKEY(info)};
}

EvpPkeyPtr LoadPrivateKey(const std::string& uri)
{
    return LoadPrivateKey(uri, nullptr, nullptr);
}

EvpPkeyPtr DeserializePrivateKey(std::span<const uint8_t> buffer)
{
    const auto& max = std::numeric_limits<int>::max();

    BioPtr bio(BIO_new_mem_buf(buffer.data(), buffer.size() > static_cast<size_t>(max) ? max : buffer.size()));
    crypto::ThrowIfTrue(bio == nullptr);

    EvpPkeyPtr key(d2i_PrivateKey_bio(bio, nullptr));
    crypto::ThrowIfTrue(key == nullptr);

    return key;
}

} // namespace snet::tls