#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

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

CryptoManager& CryptoManager::getInstance()
{
    static CryptoManager instance;
    return instance;
}

CryptoManager::~CryptoManager() noexcept
{
}

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

HashPtr CryptoManager::fetchDigest(std::string_view algorithm)
{
    auto digest = HashPtr(EVP_MD_fetch(impl_->libctx, algorithm.data(), nullptr));
    ThrowIfTrue(digest == nullptr);
    return digest;
}

CipherPtr CryptoManager::fetchCipher(std::string_view algorithm)
{
    auto cipher = CipherPtr(EVP_CIPHER_fetch(impl_->libctx, algorithm.data(), nullptr));
    ThrowIfTrue(cipher == nullptr);
    return cipher;
}

KeyCtxPtr CryptoManager::createKeyContext(std::string_view algorithm)
{
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new_from_name(impl_->libctx, algorithm.data(), nullptr));
    ThrowIfTrue(ctx == nullptr);
    return ctx;
}

KeyCtxPtr CryptoManager::createKeyContext(Key* key)
{
    auto ctx = KeyCtxPtr(EVP_PKEY_CTX_new_from_pkey(impl_->libctx, key, nullptr));
    ThrowIfTrue(ctx == nullptr);
    return ctx;
}

} // namespace snet::crypto