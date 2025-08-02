#include <string>
#include <gtest/gtest.h>

#include <casket/utils/string.hpp>

#include <snet/tls/record_decoder.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/rand.hpp>
#include <snet/crypto/cipher_context.hpp>

using namespace snet::crypto;
using namespace snet::tls;
using namespace testing;

using RecordLayerTestParam = const CipherSuite*;

std::vector<RecordLayerTestParam> GetTLSv13CipherSuites()
{
    std::vector<RecordLayerTestParam> result;
    auto cipherSuites = CipherSuiteManager::getInstance().getCipherSuites();
    for (const auto& cipherSuite : cipherSuites)
    {
        if (casket::equals(CipherSuiteGetVersion(cipherSuite), "TLSv1.3"))
        {
            result.push_back(cipherSuite);
        }
    }
    return result;
}

class RecordLayerTest : public TestWithParam<RecordLayerTestParam>
{
public:
    RecordLayerTest() = default;

    ~RecordLayerTest() = default;

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

    RecordDecoder recLayer_;
};

TEST_P(RecordLayerTest, EncryptDecrypt)
{
    const auto& param = GetParam();
    auto cipherAlg = CryptoManager::getInstance().fetchCipher(CipherSuiteGetCipherName(param));
    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(param));

    ASSERT_NE(cipherAlg, nullptr);

    std::vector<uint8_t> key(GetKeyLength(cipherAlg));
    std::vector<uint8_t> nonce(12);

    Rand::generate(key);
    Rand::generate(nonce);

    std::vector<uint8_t> plaintext = {0x16, 0x03, 0x03, 0x01, 0x02};
    std::vector<uint8_t> decryptedBuffer(32);
    std::vector<uint8_t> encryptedBuffer(32);
    nonstd::span<uint8_t> encryptedData;
    nonstd::span<uint8_t> decryptedData;

    ASSERT_NO_THROW(recLayer_.init(cipherAlg));

    ASSERT_NO_THROW(encryptedData = recLayer_.tls13Encrypt(RecordType::Handshake, 0, key, nonce, plaintext,
                                                           encryptedBuffer, tagLength));

    ASSERT_NO_THROW(decryptedData = recLayer_.tls13Decrypt(RecordType::Handshake, 0, key, nonce, encryptedData,
                                                           decryptedBuffer, tagLength));

    ASSERT_TRUE(std::equal(decryptedData.begin(), decryptedData.end(), plaintext.begin(), plaintext.end()));
}

INSTANTIATE_TEST_SUITE_P(CryptoTests, RecordLayerTest, ValuesIn(GetTLSv13CipherSuites()));
