#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

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

std::string cast_to_string(uint16_t value)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::uppercase;
    oss << "0x" << std::setw(2) << ((value >> 8) & 0xFF) << ", 0x" << std::setw(2) << (value & 0xFF);
    return oss.str();
}

TEST_P(TLSv1RecordLayerTest, EncryptDecrypt)
{
    const auto& param = GetParam();
    auto suiteCode = ::get<RecordLayerFields::Suite>(param);

    /// CHACHA20_POLY1305 doesn't support zero data length.
    if (suiteCode == casket::make_uint16(0xCC, 0xA8) || suiteCode == casket::make_uint16(0xCC, 0xA9) ||
        suiteCode == casket::make_uint16(0xCC, 0xAA))
    {
        GTEST_SKIP();
    }

    auto cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(suiteCode);
    ASSERT_NE(cipherSuite, nullptr) << "Unsupported cipher suite: " << cast_to_string(suiteCode);

    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(suiteCode);
    auto cipherAlg = CryptoManager::getInstance().fetchCipher(CipherSuiteGetCipherName(cipherSuite));
    // auto hmacAlg = CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(cipherSuite));

    ASSERT_NE(cipherAlg, nullptr);
    ASSERT_TRUE(CipherTraits::isAEAD(cipherAlg));

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

// TLS 1.2 AEAD cipher suites
constexpr std::array<uint16_t, 35> gTLSv12AeadCipherSuites = {
    // TLS 1.2 ECDHE + ECDSA (с PFS)
    casket::make_uint16(0xC0, 0x2C), /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    casket::make_uint16(0xC0, 0x30), /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    casket::make_uint16(0x00, 0xA3), /// TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
    casket::make_uint16(0x00, 0x9F), /// TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    casket::make_uint16(0xCC, 0xA9), /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    casket::make_uint16(0xCC, 0xA8), /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    casket::make_uint16(0xCC, 0xAA), /// TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    casket::make_uint16(0xC0, 0xAF), /// TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    casket::make_uint16(0xC0, 0xAD), /// TLS_ECDHE_ECDSA_WITH_AES_256_CCM
    casket::make_uint16(0xC0, 0xA3), /// TLS_DHE_RSA_WITH_AES_256_CCM_8
    casket::make_uint16(0xC0, 0x9F), /// TLS_DHE_RSA_WITH_AES_256_CCM
    casket::make_uint16(0xC0, 0x5D), /// TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
    casket::make_uint16(0xC0, 0x61), /// TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
    casket::make_uint16(0xC0, 0x57), /// TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
    casket::make_uint16(0xC0, 0x53), /// TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
    casket::make_uint16(0xC0, 0x2B), /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    casket::make_uint16(0xC0, 0x2F), /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    casket::make_uint16(0x00, 0xA2), /// TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
    casket::make_uint16(0x00, 0x9E), /// TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    casket::make_uint16(0xC0, 0xAE), /// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    casket::make_uint16(0xC0, 0xAC), /// TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    casket::make_uint16(0xC0, 0xA2), /// TLS_DHE_RSA_WITH_AES_128_CCM_8
    casket::make_uint16(0xC0, 0x9E), /// TLS_DHE_RSA_WITH_AES_128_CCM
    casket::make_uint16(0xC0, 0x5C), /// TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
    casket::make_uint16(0xC0, 0x60), /// TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
    casket::make_uint16(0xC0, 0x56), /// TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
    casket::make_uint16(0xC0, 0x52), /// TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
    // RSA without PFS (TLS 1.2)
    casket::make_uint16(0x00, 0x9D), /// TLS_RSA_WITH_AES_256_GCM_SHA384
    casket::make_uint16(0xC0, 0xA1), /// TLS_RSA_WITH_AES_256_CCM_8
    casket::make_uint16(0xC0, 0x9D), /// TLS_RSA_WITH_AES_256_CCM
    casket::make_uint16(0xC0, 0x51), /// TLS_RSA_WITH_ARIA_256_GCM_SHA384
    casket::make_uint16(0x00, 0x9C), /// TLS_RSA_WITH_AES_128_GCM_SHA256
    casket::make_uint16(0xC0, 0xA0), /// TLS_RSA_WITH_AES_128_CCM_8
    casket::make_uint16(0xC0, 0x9C), /// TLS_RSA_WITH_AES_128_CCM
    casket::make_uint16(0xC0, 0x50), /// TLS_RSA_WITH_ARIA_128_GCM_SHA256
};

/*

    // RSA without PFS (TLS 1.2)
    casket::make_uint16(0x00, 0x3D), /// TLS_RSA_WITH_AES_256_CBC_SHA256
    casket::make_uint16(0x00, 0xC0), /// TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    casket::make_uint16(0x00, 0x3C), /// TLS_RSA_WITH_AES_128_CBC_SHA256
    casket::make_uint16(0x00, 0xBA), /// TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256

    // Legacy TLS 1.0/SSLv3 (SHA1) with PFS
    casket::make_uint16(0xC0, 0x0A), /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    casket::make_uint16(0xC0, 0x14), /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    casket::make_uint16(0x00, 0x39), /// TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    casket::make_uint16(0x00, 0x38), /// TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    casket::make_uint16(0x00, 0x88), /// TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    casket::make_uint16(0x00, 0x87), /// TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
    casket::make_uint16(0xC0, 0x09), /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    casket::make_uint16(0xC0, 0x13), /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    casket::make_uint16(0x00, 0x33), /// TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    casket::make_uint16(0x00, 0x32), /// TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    casket::make_uint16(0x00, 0x45), /// TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    casket::make_uint16(0x00, 0x44), /// TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA

    // TLS 1.2 CBC mode с SHA384/SHA256 (с PFS)
    casket::make_uint16(0xC0, 0x24), /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    casket::make_uint16(0xC0, 0x28), /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    casket::make_uint16(0x00, 0x6B), /// TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    casket::make_uint16(0x00, 0x6A), /// TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    casket::make_uint16(0xC0, 0x73), /// TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
    casket::make_uint16(0xC0, 0x77), /// TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
    casket::make_uint16(0x00, 0xC4), /// TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    casket::make_uint16(0x00, 0xC3), /// TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
    casket::make_uint16(0xC0, 0x23), /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    casket::make_uint16(0xC0, 0x27), /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    casket::make_uint16(0x00, 0x67), /// TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    casket::make_uint16(0x00, 0x40), /// TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    casket::make_uint16(0xC0, 0x72), /// TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
    casket::make_uint16(0xC0, 0x76), /// TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    casket::make_uint16(0x00, 0xBE), /// TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    casket::make_uint16(0x00, 0xBD), /// TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256

    // Legacy RSA без PFS (TLS 1.0/SSLv3)
    casket::make_uint16(0x00, 0x35), /// TLS_RSA_WITH_AES_256_CBC_SHA
    casket::make_uint16(0x00, 0x84), /// TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    casket::make_uint16(0x00, 0x2F), /// TLS_RSA_WITH_AES_128_CBC_SHA
    casket::make_uint16(0x00, 0x41), /// TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
*/

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
        ValuesIn(gTLSv12AeadCipherSuites),
        ValuesIn(GenerateSequence<uint64_t, 10>(0, std::numeric_limits<uint64_t>::max())),
        ValuesIn(GenerateSequence<uint16_t, 5>(0, 2048))
    )
);

// clang-format on