#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/store_loader.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/error_code.hpp>

namespace snet::crypto::akey
{

KeyPtr shallowCopy(Key* key)
{
    if (key)
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_up_ref(key));
        return KeyPtr{key};
    }
    return nullptr;
}

KeyPtr deepCopy(Key* key)
{
    return KeyPtr{EVP_PKEY_dup(key)};
}

bool isAlgorithm(const Key* key, std::string_view alg)
{
    return EVP_PKEY_is_a(key, alg.data());
}

bool isEqual(const Key* a, const Key* b)
{
    return 0 < EVP_PKEY_eq(a, b);
}

KeyPtr fromStorage(KeyType keyType, const std::string& uri)
{
    return fromStorage(keyType, uri, UI_OpenSSL(), nullptr);
}

KeyPtr fromStorage(KeyType keyType, const std::string& uri, const UiMethod* meth, void* data)
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

    case KeyType::Public:
    {
        loadType = OSSL_STORE_INFO_PUBKEY;
        loadFn = &OSSL_STORE_INFO_get1_PUBKEY;
    }
    break;

    default:
        throw Exception(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported key type");
    }

    auto storeLoader = StoreLoader(uri, meth, data);
    auto storeInfo = storeLoader.load(loadType);
    auto result = KeyPtr{loadFn(storeInfo)};
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

KeyPtr fromFile(KeyType keyType, const std::filesystem::path& path)
{
    return fromStorage(keyType, "file:" + std::filesystem::absolute(path).string());
}

KeyPtr fromBio(KeyType keyType, Bio* in, Encoding inEncoding)
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
        throw Exception(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT),
                        "CertBuilder parse error: unsupported input BIO format");
    }
    break;
    }

    if (!result)
    {
        throw Exception(GetLastError(), "Failed to parse certificate");
    }

    return result;
}

void toBio(KeyType keyType, Key* key, Bio* bio, Encoding encoding)
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
        throw Exception(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding");
    }
    break;
    }

    if (!ret)
    {
        throw Exception(GetLastError(), "Failed to save key");
    }
}

} // namespace snet::crypto::akey

namespace snet::crypto
{

std::vector<uint8_t> GetEncodedPublicKey(const Key* key)
{
    size_t size{0};

    ThrowIfFalse(0 < EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, nullptr, 0, &size));
    ThrowIfTrue(size == OSSL_PARAM_UNMODIFIED, "unable to get public key value");

    std::vector<uint8_t> publicKey(size);
    ThrowIfFalse(0 < EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, publicKey.data(),
                                                     publicKey.size(), nullptr));
    return publicKey;
}

void SetEncodedPublicKey(Key* key, nonstd::span<const uint8_t> value)
{
    ThrowIfFalse(0 < EVP_PKEY_set1_encoded_public_key(key, value.data(), value.size_bytes()));
}

} // namespace snet::crypto