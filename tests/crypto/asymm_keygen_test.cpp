#include <gtest/gtest.h>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::crypto;

TEST(AsymmKeyGenerationTest, GenerateECKey)
{
    std::string groupName = "prime256v1";
    KeyPtr ecKey;
    ASSERT_NO_THROW(ecKey = akey::ec::generate(groupName));
    ASSERT_NE(ecKey, nullptr);
    EXPECT_TRUE(AsymmKey::isAlgorithm(ecKey, "EC"));
}

TEST(AsymmKeyGenerationTest, GenerateECKeyWithDifferentCurves)
{
    std::string groupNames[] = {"prime256v1", "secp384r1", "secp521r1"};
    KeyPtr ecKey;
    for (const auto& groupName : groupNames)
    {
        ASSERT_NO_THROW(ecKey = akey::ec::generate(groupName));
        ASSERT_NE(ecKey, nullptr);
        EXPECT_TRUE(AsymmKey::isAlgorithm(ecKey, "EC"));
    }
}

TEST(AsymmKeyGenerationTest, GenerateECKeyInvalidCurve)
{
    std::string groupName = "invalid_curve";
    ASSERT_THROW(auto ecKey = akey::ec::generate(groupName), CryptoException);
}
