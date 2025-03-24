#include <gtest/gtest.h>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::crypto;

TEST(AsymmKeyGenerationTest, GenerateRSAKey) {
    size_t keySize = 2048;
    KeyPtr rsaKey;
    ASSERT_NO_THROW(rsaKey = akey::rsa::generate(keySize));
    ASSERT_NE(rsaKey, nullptr);
    EXPECT_TRUE(akey::isAlgorithm(rsaKey, "RSA"));
}

TEST(AsymmKeyGenerationTest, GenerateRSAKeyWithDifferentSizes) {
    size_t keySizes[] = {1024, 2048, 4096};
    KeyPtr rsaKey;
    for (size_t keySize : keySizes) {
        ASSERT_NO_THROW(rsaKey = akey::rsa::generate(keySize));
        ASSERT_NE(rsaKey, nullptr);
        EXPECT_TRUE(akey::isAlgorithm(rsaKey, "RSA"));
    }
}

TEST(AsymmKeyGenerationTest, GenerateRSAKeyInvalidSize) {
    size_t keySize = 511;
    ASSERT_THROW(auto rsaKey = akey::rsa::generate(keySize), Exception);
}

TEST(AsymmKeyGenerationTest, GenerateECKey) {
    std::string groupName = "prime256v1";
    KeyPtr ecKey;
    ASSERT_NO_THROW(ecKey = akey::ec::generate(groupName));
    ASSERT_NE(ecKey, nullptr);
    EXPECT_TRUE(akey::isAlgorithm(ecKey, "EC"));
}

TEST(AsymmKeyGenerationTest, GenerateECKeyWithDifferentCurves) {
    std::string groupNames[] = {"prime256v1", "secp384r1", "secp521r1"};
    KeyPtr ecKey;
    for (const auto& groupName : groupNames) {
        ASSERT_NO_THROW(ecKey = akey::ec::generate(groupName));
        ASSERT_NE(ecKey, nullptr);
        EXPECT_TRUE(akey::isAlgorithm(ecKey, "EC"));
    }
}

TEST(AsymmKeyGenerationTest, GenerateECKeyInvalidCurve) {
    std::string groupName = "invalid_curve";
    ASSERT_THROW(auto ecKey = akey::ec::generate(groupName), Exception);
}
