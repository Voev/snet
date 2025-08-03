#include <string>
#include <gtest/gtest.h>

#include <casket/utils/string.hpp>

#include <snet/tls/record_layer.hpp>
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

    std::vector<uint8_t> plaintext = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};

    auto ctx = CreateCipherCtx();

    ASSERT_NO_THROW(RecordLayer::init(ctx, cipherAlg));

    RecordLayer recordLayer;

    recordLayer.setVersion(ProtocolVersion::TLSv1_3);
    recordLayer.enableAEAD();
    recordLayer.setTagLength(tagLength);

    Record record(RecordType::ApplicationData);
    record.initPlaintext(plaintext);

    ASSERT_NO_THROW(recordLayer.doTLSv13Encrypt(ctx, &record, 0, key, nonce));
    ASSERT_NO_THROW(recordLayer.doTLSv13Decrypt(ctx, &record, 0, key, nonce));

    auto decryptedData = record.getPlaintext();
    ASSERT_TRUE(std::equal(decryptedData.begin(), decryptedData.end(), plaintext.begin(), plaintext.end()));
}

INSTANTIATE_TEST_SUITE_P(CryptoTests, RecordLayerTest, ValuesIn(GetTLSv13CipherSuites()));
