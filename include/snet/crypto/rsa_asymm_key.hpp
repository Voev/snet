#pragma once
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

class RsaAsymmKey final
{
public:
    static KeyPtr generate(size_t bits);

    static void setPssSettings(KeyCtx* ctx)
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING));
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST));
    }
};

} // namespace snet::crypto