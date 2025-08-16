#include <gtest/gtest.h>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::crypto;
using namespace testing;

class RsaAsymmKeyGenerationTest : public TestWithParam<size_t>
{
};

TEST_P(RsaAsymmKeyGenerationTest, GenerateRSAKey)
{
    size_t keySize = 2048;
    KeyPtr rsaKey;
    ASSERT_NO_THROW(rsaKey = RsaAsymmKey::generate(keySize));
    ASSERT_NE(rsaKey, nullptr);
    EXPECT_TRUE(AsymmKey::isAlgorithm(rsaKey, "RSA"));
}

INSTANTIATE_TEST_CASE_P(RSA, RsaAsymmKeyGenerationTest, Values(1024, 2048, 4096));

class RsaAsymmKeyGenerationNegativeTest : public Test
{
};

TEST(RsaAsymmKeyGenerationNegativeTest, InvalidKeySize)
{
    size_t keySize = 511;
    ASSERT_THROW(auto rsaKey = RsaAsymmKey::generate(keySize), CryptoException);
}
