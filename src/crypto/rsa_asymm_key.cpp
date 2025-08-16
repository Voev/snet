#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/crypto_manager.hpp>

namespace snet::crypto
{

KeyPtr RsaAsymmKey::generate(size_t bits)
{
    EVP_PKEY* pkey{nullptr};
    crypto::KeyCtxPtr ctx{CryptoManager::getInstance().createKeyContext("RSA")};
    crypto::ThrowIfFalse(ctx != nullptr);
    crypto::ThrowIfFalse(0 < EVP_PKEY_keygen_init(ctx));
    crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits));
    crypto::ThrowIfFalse(0 < EVP_PKEY_keygen(ctx, &pkey));
    return crypto::KeyPtr{pkey};
}

} // namespace snet::crypto