#include <string>
#include <gtest/gtest.h>

#include <casket/utils/string.hpp>

#include <snet/tls/record_layer.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/rand.hpp>
#include <snet/crypto/cipher_traits.hpp>

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

template <typename T, size_t N>
constexpr std::array<T, N> GenerateSequence(T start, T step = 1)
{
    static_assert(std::is_arithmetic_v<T>, "T must be an arithmetic type");
    std::array<T, N> sequence{};
    T value = start;
    for (size_t i = 0; i < N; ++i)
    {
        sequence[i] = value;
        value += step;
    }
    return sequence;
}

// clang-format off

INSTANTIATE_TEST_SUITE_P(CryptoTests, RecordLayerTest,
    Combine(
        ValuesIn(gTLSv13CipherSuites),
        ValuesIn(GenerateSequence<uint64_t, 10>(0UL, 2049638230412172401UL)),
        ValuesIn(GenerateSequence<uint16_t, 5>(0UL, 1024UL))
    )
);

// clang-format on
