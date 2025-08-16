#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet;

namespace
{

static crypto::KeyPtr generateWithParams(OSSL_LIB_CTX* libctx, const char* name, const char* propq,
                                         const OSSL_PARAM* params)
{
    EVP_PKEY* pkey{nullptr};
    crypto::KeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(libctx, name, propq));
    crypto::ThrowIfFalse(ctx != nullptr);
    crypto::ThrowIfFalse(0 < EVP_PKEY_keygen_init(ctx));
    crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));
    crypto::ThrowIfFalse(0 < EVP_PKEY_generate(ctx, &pkey));
    return crypto::KeyPtr{pkey};
}

} // namespace

namespace snet::crypto::akey
{

namespace ec
{

KeyPtr generate(std::string_view groupName, OSSL_LIB_CTX* libctx, const char* propq)
{
    OSSL_PARAM params[] = {OSSL_PARAM_END, OSSL_PARAM_END};

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>(groupName.data()), 0);

    return ::generateWithParams(libctx, "EC", propq, params);
}

} // namespace ec

} // namespace snet::crypto::akey