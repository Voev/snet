#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/tls/exchange.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

namespace snet::tls
{

SecureVector<uint8_t> ExchangeSecret(Key* privateKey, Key* publicKey, bool isTLSv3)
{
    size_t secretLength = 0;
    
    auto ctx = CipherSuiteManager::getInstance().createKeyContext(privateKey);

    crypto::ThrowIfFalse(0 < EVP_PKEY_derive_init(ctx));
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive_set_peer(ctx, publicKey));
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive(ctx, nullptr, &secretLength));
    
    if (isTLSv3 && EVP_PKEY_is_a(privateKey, "DH"))
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_dh_pad(ctx, 1));
    }
    
    SecureVector<uint8_t> secret(secretLength);
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive(ctx, secret.data(), &secretLength));
    secret.resize(secretLength);
    return secret;
}

} // namespace snet::tls