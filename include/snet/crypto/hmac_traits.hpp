#pragma once
#include <cstdint>
#include <openssl/evp.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#endif

#include <casket/nonstd/span.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

class HmacTraits
{
public:
    static inline MacCtxPtr createContext()
    {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        auto mac = crypto::CryptoManager::getInstance().fetchMac("HMAC");
        auto ctx = MacCtxPtr{EVP_MAC_CTX_new(mac)};
#else  // ^(OPENSSL_VERSION_NUMBER >= 0x30000000L)
        auto ctx = MacCtxPtr{HMAC_CTX_new()};
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
        ThrowIfTrue(ctx == nullptr, "failed to create HMAC context");
        return ctx;
    }

    static inline void initHmac(MacCtx* ctx, const Hash* algorithm, nonstd::span<const uint8_t> key)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        char* digest = const_cast<char*>(HashTraits::getName(algorithm));

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
        params[1] = OSSL_PARAM_construct_end();

        ThrowIfFalse(0 < EVP_MAC_CTX_set_params(ctx, params));
        ThrowIfFalse(0 < EVP_MAC_init(ctx, key.data(), key.size(), nullptr));
#else  // ^(OPENSSL_VERSION_NUMBER >= 0x30000000L)
        ThrowIfFalse(0 < HMAC_Init_ex(ctx, key.data(), key.size(), algorithm, nullptr));
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
    }

    static inline void updateHmac(MacCtx* ctx, nonstd::span<const uint8_t> message)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        ThrowIfFalse(0 < EVP_MAC_update(ctx, message.data(), message.size()));
#else  // ^(OPENSSL_VERSION_NUMBER >= 0x30000000L)
        ThrowIfFalse(0 < HMAC_Update(ctx, message.data(), message.size()));
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
    }

    static inline nonstd::span<uint8_t> finalHmac(MacCtx* ctx, nonstd::span<uint8_t> buffer)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        size_t hmacSize = 0;
        ThrowIfFalse(0 < EVP_MAC_final(ctx, buffer.data(), &hmacSize, buffer.size()));
#else  // ^(OPENSSL_VERSION_NUMBER >= 0x30000000L)
        unsigned int hmacSize = buffer.size();
        ThrowIfFalse(0 < HMAC_Final(ctx, buffer.data(), &hmacSize));
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)

        return {buffer.data(), hmacSize};
    }
};

} // namespace snet::crypto
