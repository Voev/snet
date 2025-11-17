#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

struct CryptoManager::Impl final
{
public:
    Impl()
        : libctx(nullptr)
    {
    }

    ~Impl() noexcept
    {
    }

    OSSL_LIB_CTX* libctx;
};

CryptoManager::CryptoManager()
    : impl_(std::make_unique<Impl>())
{
}

#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

CryptoManager::CryptoManager()
{
}

CryptoManager& CryptoManager::getInstance()
{
    static CryptoManager instance;
    return instance;
}

CryptoManager::~CryptoManager() noexcept
{
}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

MacPtr CryptoManager::fetchMac(std::string_view algorithm)
{
    auto mac = MacPtr(EVP_MAC_fetch(impl_->libctx, algorithm.data(), nullptr));
    ThrowIfTrue(mac == nullptr);
    return mac;
}

KdfPtr CryptoManager::fetchKdf(std::string_view algorithm)
{
    auto kdf = KdfPtr(EVP_KDF_fetch(impl_->libctx, algorithm.data(), nullptr));
    ThrowIfTrue(kdf == nullptr);
    return kdf;
}

#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

HashPtr CryptoManager::fetchDigest(std::string_view algorithm)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    auto digest = HashPtr(EVP_MD_fetch(impl_->libctx, algorithm.data(), nullptr));
#else
    auto digest = EVP_get_digestbyname(algorithm.data());
#endif
    ThrowIfTrue(digest == nullptr);
    return digest;
}

CipherPtr CryptoManager::fetchCipher(std::string_view algorithm)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    auto cipher = CipherPtr(EVP_CIPHER_fetch(impl_->libctx, algorithm.data(), nullptr));
#else
    auto cipher = EVP_get_cipherbyname(algorithm.data());
#endif
    ThrowIfTrue(cipher == nullptr);
    return cipher;
}

KeyCtxPtr CryptoManager::createKeyContext(std::string_view algorithm)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new_from_name(impl_->libctx, algorithm.data(), nullptr));
#else
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new_id(OBJ_sn2nid(algorithm.data()), nullptr));
#endif
    ThrowIfTrue(ctx == nullptr);
    return ctx;
}

KeyCtxPtr CryptoManager::createKeyContext(Key* key)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new_from_pkey(impl_->libctx, key, nullptr));
#else
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new(key, nullptr));
#endif
    ThrowIfTrue(ctx == nullptr);
    return ctx;
}

} // namespace snet::crypto