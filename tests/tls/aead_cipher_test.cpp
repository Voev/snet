#include <gtest/gtest.h>
#include <snet/tls/record/aead_cipher.hpp>
#include <openssl/evp.h>

#include <snet/crypto/exception.hpp>

using namespace snet;
using namespace snet::tls;

class AeadCipherTest : public ::testing::Test {
protected:
    void SetUp() override {
        ctx = EVP_CIPHER_CTX_new();
        ASSERT_NE(ctx, nullptr);
        
        // Используем AES-256-GCM для тестов
        cipher = EVP_aes_256_gcm();
        ASSERT_NE(cipher, nullptr);
        
        // Инициализация тестовых данных
        memset(key, 0x01, sizeof(key));
        memset(iv, 0x02, sizeof(iv));
        memset(aad, 0x03, sizeof(aad));
        memset(plaintext, 0x04, sizeof(plaintext));
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(tag, 0, sizeof(tag));
        
        op.key = key;
        op.iv = iv;
        op.aad = aad;
        op.plaintext = plaintext;
        op.ciphertext = ciphertext;
        op.tag = tag;
        
        op.keyLength = sizeof(key);
        op.ivLength = sizeof(iv);
        op.aadLength = sizeof(aad);
        op.plaintextLength = sizeof(plaintext);
        op.ciphertextLength = sizeof(ciphertext);
        op.tagLength = sizeof(tag);
    }
    
    void TearDown() override {
        EVP_CIPHER_CTX_free(ctx);
    }
    
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher;
    
    // Тестовые данные
    unsigned char key[32]; // 256 бит для AES-256
    unsigned char iv[12];  // 96 бит для GCM
    unsigned char aad[16];
    unsigned char plaintext[64];
    unsigned char ciphertext[64];
    unsigned char tag[16];
    
    CipherOperation op;
};

TEST_F(AeadCipherTest, EncryptInitSuccess) {
    EXPECT_NO_THROW(AeadCipher::encryptInit(ctx, cipher));
}

TEST_F(AeadCipherTest, EncryptInitFailure) {
    EXPECT_THROW(AeadCipher::encryptInit(nullptr, cipher), crypto::Exception);
}

TEST_F(AeadCipherTest, DecryptInitSuccess) {
    EXPECT_NO_THROW(AeadCipher::decryptInit(ctx, cipher));
}

TEST_F(AeadCipherTest, DecryptInitFailure) {
    EXPECT_THROW(AeadCipher::decryptInit(nullptr, cipher), crypto::Exception);
}

TEST_F(AeadCipherTest, EncryptDecryptRoundtrip) {
    // Шаг 1: Инициализация шифрования
    AeadCipher::encryptInit(ctx, cipher);
    
    // Шаг 2: Шифрование данных
    EXPECT_NO_THROW(AeadCipher::encrypt(ctx, cipher, op));
    
    // Проверяем, что ciphertext и tag изменились
    EXPECT_NE(memcmp(ciphertext, plaintext, sizeof(plaintext)), 0);
    //EXPECT_NE(memcmp(tag, 0, sizeof(tag)), 0);
    
    // Сохраняем зашифрованные данные и тег для последующего расшифрования
    unsigned char savedCiphertext[sizeof(ciphertext)];
    unsigned char savedTag[sizeof(tag)];
    memcpy(savedCiphertext, ciphertext, sizeof(ciphertext));
    memcpy(savedTag, tag, sizeof(tag));
    
    // Шаг 3: Инициализация расшифрования
    AeadCipher::decryptInit(ctx, cipher);
    
    // Восстанавливаем оригинальные данные для операции расшифрования
    op.ciphertext = savedCiphertext;
    op.tag = savedTag;
    memset(plaintext, 0, sizeof(plaintext)); // Очищаем буфер для plaintext
    
    // Шаг 4: Расшифрование данных
    EXPECT_NO_THROW(AeadCipher::decrypt(ctx, op));
    
    // Проверяем, что получили исходные данные
    unsigned char expectedPlaintext[sizeof(plaintext)];
    memset(expectedPlaintext, 0x04, sizeof(expectedPlaintext));
    EXPECT_EQ(memcmp(op.plaintext, expectedPlaintext, sizeof(expectedPlaintext)), 0);
}

TEST_F(AeadCipherTest, DecryptWithWrongTag) {
    // Шаг 1: Инициализация и шифрование
    AeadCipher::encryptInit(ctx, cipher);
    AeadCipher::encrypt(ctx, cipher, op);
    
    // Шаг 2: Портим тег
    op.tag[0] ^= 0xFF;
    
    // Шаг 3: Инициализация расшифрования
    AeadCipher::decryptInit(ctx, cipher);
    
    // Шаг 4: Попытка расшифрования с неправильным тегом
    EXPECT_THROW(AeadCipher::decrypt(ctx, op), crypto::Exception);
}

TEST_F(AeadCipherTest, DecryptWithWrongKey) {
    // Шаг 1: Инициализация и шифрование
    AeadCipher::encryptInit(ctx, cipher);
    AeadCipher::encrypt(ctx, cipher, op);
    
    // Сохраняем зашифрованные данные
    unsigned char savedCiphertext[sizeof(ciphertext)];
    unsigned char savedTag[sizeof(tag)];
    memcpy(savedCiphertext, ciphertext, sizeof(ciphertext));
    memcpy(savedTag, tag, sizeof(tag));
    
    // Шаг 2: Меняем ключ
    unsigned char wrongKey[sizeof(key)];
    memset(wrongKey, 0xFF, sizeof(wrongKey));
    op.key = wrongKey;
    op.ciphertext = savedCiphertext;
    op.tag = savedTag;
    memset(plaintext, 0, sizeof(plaintext));
    
    // Шаг 3: Инициализация расшифрования
    AeadCipher::decryptInit(ctx, cipher);
    
    // Шаг 4: Попытка расшифрования с неправильным ключом
    EXPECT_THROW(AeadCipher::decrypt(ctx, op), crypto::Exception);
}

TEST_F(AeadCipherTest, EncryptWithInvalidParameters) {
    CipherOperation invalidOp = op;
    invalidOp.key = nullptr;
    EXPECT_THROW(AeadCipher::encrypt(ctx, cipher, invalidOp), crypto::Exception);
    
    invalidOp = op;
    invalidOp.iv = nullptr;
    EXPECT_THROW(AeadCipher::encrypt(ctx, cipher, invalidOp), crypto::Exception);
    
    invalidOp = op;
    invalidOp.ivLength = 0;
    EXPECT_THROW(AeadCipher::encrypt(ctx, cipher, invalidOp), crypto::Exception);
}