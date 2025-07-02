#include <openssl/evp.h>
#include <snet/crypto/signature.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/crypto_manager.hpp>

namespace snet::crypto
{

std::vector<uint8_t> signDigest(Key* privateKey, const Hash* hash, nonstd::span<const uint8_t> messageDigest)
{

    KeyCtxPtr ctx = CryptoManager::getInstance().createKeyContext(privateKey);
    ThrowIfFalse(ctx != nullptr, "failed to create key context");
    ThrowIfFalse(0 < EVP_PKEY_sign_init(ctx));

    if (EVP_PKEY_is_a(privateKey, "RSA"))
    {
        ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING));
    }

    ThrowIfFalse(0 < EVP_PKEY_CTX_set_signature_md(ctx, hash));

    size_t siglen{0};
    ThrowIfFalse(0 < EVP_PKEY_sign(ctx, nullptr, &siglen, messageDigest.data(), messageDigest.size()));

    std::vector<uint8_t> sig(siglen);
    ThrowIfFalse(0 < EVP_PKEY_sign(ctx, sig.data(), &siglen, messageDigest.data(), messageDigest.size()));
    sig.resize(siglen);

    return sig;
}

bool verifyDigest(Key* publicKey, const Hash* hash, nonstd::span<const uint8_t> messageDigest,
                  nonstd::span<const uint8_t> signature)
{
    KeyCtxPtr ctx = CryptoManager::getInstance().createKeyContext(publicKey);
    
    ThrowIfFalse(ctx != nullptr, "failed to create key context");
    ThrowIfFalse(0 < EVP_PKEY_verify_init(ctx));

    if (EVP_PKEY_is_a(publicKey, "RSA"))
    {
        ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING));
    }

    ThrowIfFalse(0 < EVP_PKEY_CTX_set_signature_md(ctx, hash));

    return (0 < EVP_PKEY_verify(ctx, signature.data(), signature.size(), messageDigest.data(), messageDigest.size()));
}

// Функция для вычисления хеша (SHA-256)
int compute_hash(const unsigned char *data, size_t data_len, unsigned char **hash, size_t *hash_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256(); // Можно заменить на EVP_sha512(), EVP_sha3_256() и т. д.

    if (!md_ctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return 0;
    }

    // Инициализируем контекст хеширования
    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
        fprintf(stderr, "Error initializing hash\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    // Вычисляем хеш
    *hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md));
    if (!*hash) {
        fprintf(stderr, "Error allocating memory for hash\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (EVP_DigestUpdate(md_ctx, data, data_len) != 1) {
        fprintf(stderr, "Error updating hash\n");
        OPENSSL_free(*hash);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (EVP_DigestFinal_ex(md_ctx, *hash, (unsigned int *)hash_len) != 1) {
        fprintf(stderr, "Error finalizing hash\n");
        OPENSSL_free(*hash);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

/*
// Функция для подписи хеша
int sign_hash(const unsigned char *hash, size_t hash_len, EVP_PKEY *private_key, unsigned char **signature, size_t *signature_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    int ret = 0;

    if (!md_ctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return 0;
    }

    // Инициализируем подпись (хеш уже вычислен, поэтому указываем NULL для алгоритма)
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, private_key) != 1) {
        fprintf(stderr, "Error initializing signing\n");
        goto cleanup;
    }

    // Указываем, что подписываем "сырые" данные (хеш)
    if (EVP_PKEY_CTX_set_signature_md(EVP_MD_CTX_pkey_ctx(md_ctx), NULL) != 1) {
        fprintf(stderr, "Error setting signature MD (raw mode)\n");
        goto cleanup;
    }

    // Определяем размер подписи
    if (EVP_DigestSign(md_ctx, NULL, signature_len, hash, hash_len) != 1) {
        fprintf(stderr, "Error getting signature length\n");
        goto cleanup;
    }

    *signature = (unsigned char *)OPENSSL_malloc(*signature_len);
    if (!*signature) {
        fprintf(stderr, "Error allocating memory for signature\n");
        goto cleanup;
    }

    // Подписываем хеш
    if (EVP_DigestSign(md_ctx, *signature, signature_len, hash, hash_len) != 1) {
        fprintf(stderr, "Error signing hash\n");
        OPENSSL_free(*signature);
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    return ret;
}

int main() {
    const char *private_key_path = "private.pem";
    const char *data = "Hello, world!";
    size_t data_len = strlen(data);

    FILE *key_file = fopen(private_key_path, "rb");
    if (!key_file) {
        fprintf(stderr, "Error opening private key file\n");
        return 1;
    }

    // Загружаем закрытый ключ
    EVP_PKEY *private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!private_key) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 1. Хешируем данные
    unsigned char *hash = NULL;
    size_t hash_len = 0;
    if (!compute_hash((const unsigned char *)data, data_len, &hash, &hash_len)) {
        fprintf(stderr, "Error computing hash\n");
        EVP_PKEY_free(private_key);
        return 1;
    }

    printf("Hash (%zu bytes): ", hash_len);
    for (size_t i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // 2. Подписываем хеш
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    if (!sign_hash(hash, hash_len, private_key, &signature, &signature_len)) {
        fprintf(stderr, "Error signing hash\n");
        OPENSSL_free(hash);
        EVP_PKEY_free(private_key);
        return 1;
    }

    printf("Signature (%zu bytes): ", signature_len);
    for (size_t i = 0; i < signature_len; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    // Освобождаем ресурсы
    OPENSSL_free(hash);
    OPENSSL_free(signature);
    EVP_PKEY_free(private_key);

    return 0;
}*/

} // namespace snet::crypto