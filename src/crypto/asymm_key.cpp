#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/err.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/store_loader.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/error_code.hpp>

#include <snet/utils/finally.hpp>

namespace snet::crypto
{

KeyPtr AsymmKey::shallowCopy(Key* key)
{
    if (key)
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_up_ref(key));
        return KeyPtr{key};
    }
    return nullptr;
}

bool AsymmKey::isAlgorithm(const Key* key, std::string_view alg)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return EVP_PKEY_is_a(key, alg.data());
#else  // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    const auto nid = OBJ_sn2nid(alg.data());
    return EVP_PKEY_base_id(key) == nid;
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
}

bool AsymmKey::isEqual(const Key* a, const Key* b)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return 0 < EVP_PKEY_eq(a, b);
#else  // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return 0 < EVP_PKEY_cmp(a, b);
#endif //!(OPENSSL_VERSION_NUMBER >= 0x30000000L)
}

KeyPtr AsymmKey::fromStorage(KeyType keyType, const std::string& uri)
{
    return fromStorage(keyType, uri, UI_OpenSSL(), nullptr);
}

KeyPtr AsymmKey::fromStorage(KeyType keyType, const std::string& uri, const UiMethod* meth, void* data)
{
    using LoadFn = Key* (*)(const StoreInfo*);

    int loadType;
    LoadFn loadFn;

    switch (keyType)
    {
    case KeyType::Private:
    {
        loadType = OSSL_STORE_INFO_PKEY;
        loadFn = &OSSL_STORE_INFO_get1_PKEY;
    }
    break;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    case KeyType::Public:
    {
        loadType = OSSL_STORE_INFO_PUBKEY;
        loadFn = &OSSL_STORE_INFO_get1_PUBKEY;
    }
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    break;

    default:
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported key type");
    }

    auto storeLoader = StoreLoader(uri, meth, data);
    auto storeInfo = storeLoader.load(loadType);
    auto result = KeyPtr{loadFn(storeInfo)};
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

KeyPtr AsymmKey::fromFile(KeyType keyType, const std::filesystem::path& path)
{
    return fromStorage(keyType, "file:" + std::filesystem::absolute(path).string());
}

KeyPtr AsymmKey::fromBio(KeyType keyType, Bio* in, Encoding inEncoding)
{
    KeyPtr result;

    switch (inEncoding)
    {
    case Encoding::DER:
    {
        if (keyType == KeyType::Public)
        {
            result.reset(d2i_PUBKEY_bio(in, NULL));
        }
        else
        {
            result.reset(d2i_PrivateKey_bio(in, NULL));
        }
    }
    break;

    case Encoding::PEM:
    {
        if (keyType == KeyType::Public)
        {
            result.reset(PEM_read_bio_PUBKEY(in, NULL, NULL, NULL));
        }
        else
        {
            result.reset(PEM_read_bio_PrivateKey(in, NULL, NULL, NULL));
        }
    }
    break;

    default:
    {
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT),
                              "CertBuilder parse error: unsupported input BIO format");
    }
    break;
    }

    if (!result)
    {
        throw CryptoException(GetLastError(), "Failed to parse certificate");
    }

    return result;
}

void AsymmKey::toBio(KeyType keyType, Key* key, Bio* bio, Encoding encoding)
{
    int ret{0};

    switch (encoding)
    {
    case Encoding::DER:
    {
        if (keyType == KeyType::Public)
        {
            ret = i2d_PUBKEY_bio(bio, key);
        }
        else
        {
            ret = i2d_PrivateKey_bio(bio, key);
        }
    }
    break;

    case Encoding::PEM:
    {
        if (keyType == KeyType::Public)
        {
            ret = PEM_write_bio_PUBKEY(bio, key);
        }
        else
        {
            ret = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
        }
    }
    break;

    default:
    {
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding");
    }
    break;
    }

    if (!ret)
    {
        throw CryptoException(GetLastError(), "Failed to save key");
    }
}

std::vector<uint8_t> AsymmKey::getEncodedPublicKey(const Key* key)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    size_t size{0};

    ThrowIfFalse(0 < EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &size));
    ThrowIfTrue(size == OSSL_PARAM_UNMODIFIED, "unable to get public key value");

    std::vector<uint8_t> publicKey(size);
    ThrowIfFalse(0 < EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, publicKey.data(),
                                                     publicKey.size(), nullptr));
    return publicKey;
#else  // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    unsigned char* buffer{nullptr};
    size_t length;

    length = EVP_PKEY_get1_tls_encodedpoint(const_cast<Key*>(key), &buffer);
    ThrowIfFalse(buffer != nullptr);

    auto _ = Finally([&buffer]() { OPENSSL_free(buffer); });

    return std::vector<uint8_t>(buffer, buffer + length);
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
}

void AsymmKey::setEncodedPublicKey(Key* key, nonstd::span<const uint8_t> value)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    ThrowIfFalse(0 < EVP_PKEY_set1_encoded_public_key(key, value.data(), value.size_bytes()));
#else  // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    ThrowIfFalse(0 < EVP_PKEY_set1_tls_encodedpoint(key, value.data(), value.size_bytes()));
#endif // !(OPENSSL_VERSION_NUMBER >= 0x30000000L)
}

} // namespace snet::crypto