#include <openssl/store.h>
#include <snet/crypto/store_loader.hpp>
#include <snet/crypto/exception.hpp>

namespace
{

std::string storeInfoTypeToStr(int type)
{
    switch (type)
    {
    case OSSL_STORE_INFO_NAME:
        return "X509_NAME";
    case OSSL_STORE_INFO_PARAMS:
        return "PARAMS";
    case OSSL_STORE_INFO_PKEY:
        return "PKEY";
    case OSSL_STORE_INFO_CERT:
        return "CERT";
    case OSSL_STORE_INFO_CRL:
        return "CRL";
    default:
        return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

} // namespace

namespace snet::crypto
{

StoreLoader::StoreLoader(std::string_view uri, const UiMethod* meth, void* data)
    : ctx_(OSSL_STORE_open(uri.data(), meth, data, nullptr, nullptr))
{

    crypto::ThrowIfTrue(ctx_ == nullptr);
}

void StoreLoader::expect(int type)
{
    crypto::ThrowIfFalse(OSSL_STORE_expect(ctx_, type));
}

bool StoreLoader::isError()
{
    return OSSL_STORE_error(ctx_);
}

bool StoreLoader::finished()
{
    return OSSL_STORE_eof(ctx_);
}

StoreInfoPtr StoreLoader::load(int type)
{
    expect(type);
    auto result = StoreInfoPtr(OSSL_STORE_load(ctx_));
    crypto::ThrowIfTrue(isError(), "failed to load object of type: " + storeInfoTypeToStr(type));
    crypto::ThrowIfTrue(result == nullptr);
    return result;
}

} // namespace snet::crypto