#include <string>
#include <gtest/gtest.h>
#include <casket/utils/string.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/rand.hpp>
#include <snet/crypto/cipher_traits.hpp>
#include <snet/crypto/hmac_traits.hpp>

using namespace snet::crypto;
using namespace snet::tls;
using namespace testing;

enum class RecordLayerFields
{
    Suite,
    Seqnum,
    DataSize
};

using RecordLayerTestParam = std::tuple<uint16_t, uint64_t, uint16_t>;

template <RecordLayerFields field, typename Tuple>
auto& get(Tuple& tuple)
{
    return std::get<static_cast<size_t>(field)>(tuple);
}

class RecordLayerTest : public TestWithParam<RecordLayerTestParam>
{
};

TEST_P(RecordLayerTest, EncryptDecrypt)
{
    const auto& param = GetParam();
    auto cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(::get<RecordLayerFields::Suite>(param));
    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(::get<RecordLayerFields::Suite>(param));
    auto cipherAlg = CryptoManager::getInstance().fetchCipher(CipherSuiteGetCipherName(cipherSuite));

    ASSERT_NE(cipherAlg, nullptr);

    std::vector<uint8_t> key(CipherTraits::getKeyLength(cipherAlg));
    std::vector<uint8_t> nonce(12);
    std::vector<uint8_t> plaintext(::get<RecordLayerFields::DataSize>(param));

    Rand::generate(key);
    Rand::generate(nonce);
    Rand::generate(plaintext);

    CipherCtxPtr ctx;

    ASSERT_NO_THROW(ctx = CipherTraits::createContext());
    ASSERT_NO_THROW(RecordLayer::init(ctx, cipherAlg));

    RecordLayer recordLayer;

    recordLayer.setVersion(ProtocolVersion::TLSv1_3);
    recordLayer.enableAEAD();
    recordLayer.setTagLength(tagLength);

    Record record(RecordType::ApplicationData);
    record.initPlaintext(plaintext);

    ASSERT_NO_THROW(recordLayer.doTLSv13Encrypt(ctx, &record, ::get<RecordLayerFields::Seqnum>(param), key, nonce));
    ASSERT_NO_THROW(recordLayer.doTLSv13Decrypt(ctx, &record, ::get<RecordLayerFields::Seqnum>(param), key, nonce));

    auto decryptedData = record.getPlaintext();
    ASSERT_TRUE(std::equal(decryptedData.begin(), decryptedData.end(), plaintext.begin(), plaintext.end()));
}

static std::array<uint16_t, 5> gTLSv13CipherSuites = {
    casket::make_uint16(0x13, 0x01), /// TLS_AES_128_GCM_SHA256
    casket::make_uint16(0x13, 0x02), /// TLS_AES_256_GCM_SHA384
    casket::make_uint16(0x13, 0x03), /// TLS_CHACHA20_POLY1305_SHA256
    casket::make_uint16(0x13, 0x04), /// TLS_AES_128_CCM_SHA256
    casket::make_uint16(0x13, 0x05), /// TLS_AES_128_CCM_8_SHA256
};

class TLSv1RecordLayerTest : public TestWithParam<RecordLayerTestParam>
{
};

TEST_P(TLSv1RecordLayerTest, EncryptDecrypt)
{
    const auto& param = GetParam();
    auto cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(::get<RecordLayerFields::Suite>(param));
    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(::get<RecordLayerFields::Suite>(param));
    auto cipherAlg = CryptoManager::getInstance().fetchCipher(CipherSuiteGetCipherName(cipherSuite));
    // auto hmacAlg = CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(cipherSuite));

    ASSERT_NE(cipherAlg, nullptr);

    std::vector<uint8_t> key(CipherTraits::getKeyLength(cipherAlg));
    std::vector<uint8_t> iv(CipherTraits::getIVLengthWithinKeyBlock(cipherAlg));
    std::vector<uint8_t> plaintext(::get<RecordLayerFields::DataSize>(param));

    Rand::generate(key);
    Rand::generate(iv);
    Rand::generate(plaintext);

    CipherCtxPtr ctx;

    ASSERT_NO_THROW(ctx = CipherTraits::createContext());
    ASSERT_NO_THROW(RecordLayer::init(ctx, cipherAlg));

    /*MacCtxPtr hmacCtx;
    ASSERT_NO_THROW(hmacCtx = HmacTraits::createContext());

    HashCtxPtr hashCtx;
    ASSERT_NO_THROW(hashCtx = HashTraits::createContext());
*/
    RecordLayer recordLayer;

    recordLayer.setVersion(ProtocolVersion::TLSv1_2);
    recordLayer.enableAEAD();
    recordLayer.setTagLength(tagLength);

    Record record(RecordType::ApplicationData);

    recordLayer.prepareRecordForEncrypt(&record, cipherAlg);

    record.initPlaintext(plaintext);

    ASSERT_NO_THROW(recordLayer.doTLSv1AeadEncrypt(ctx, &record, ::get<RecordLayerFields::Seqnum>(param), key, iv));
    ASSERT_NO_THROW(recordLayer.doTLSv1AeadDecrypt(ctx, /*hmacCtx, hashCtx, nullptr,*/ &record,
                                                   ::get<RecordLayerFields::Seqnum>(param), key, iv));

    auto decryptedData = record.getPlaintext();
    ASSERT_TRUE(std::equal(decryptedData.begin(), decryptedData.end(), plaintext.begin(), plaintext.end()));
}

static std::array<uint16_t, 1> gTLSv1CipherSuites = {
    casket::make_uint16(0xC0, 0x9D)
    // casket::make_uint16(0xC0, 0x2B)
};

template <typename T, size_t N>
constexpr std::array<T, N> GenerateSequence(T start, T end)
{
    static_assert(std::is_arithmetic_v<T>, "T must be an arithmetic type");
    static_assert(N > 1, "Need at least 2 elements for range");
    std::array<T, N> sequence{};
    T step = (end - start) / (N - 1);
    for (size_t i = 0; i < N; ++i)
    {
        sequence[i] = start + static_cast<T>(i) * step;
    }
    return sequence;
}

// clang-format off

INSTANTIATE_TEST_SUITE_P(CryptoTests, RecordLayerTest,
    Combine(
        ValuesIn(gTLSv13CipherSuites),
        ValuesIn(GenerateSequence<uint64_t, 10>(0, std::numeric_limits<uint64_t>::max())),
        ValuesIn(GenerateSequence<uint16_t, 5>(0, 2048))
    )
);

INSTANTIATE_TEST_SUITE_P(CryptoTests, TLSv1RecordLayerTest,
    Combine(
        ValuesIn(gTLSv1CipherSuites),
        ValuesIn(GenerateSequence<uint64_t, 10>(0, std::numeric_limits<uint64_t>::max())),
        ValuesIn(GenerateSequence<uint16_t, 5>(0, 2048))
    )
);

// clang-format on