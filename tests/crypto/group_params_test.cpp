#include <gtest/gtest.h>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::crypto;
using namespace testing;

using GenerationTestParam = GroupParams;
using DeriveTestParam = std::tuple<GroupParams, bool>;

static std::string GenerationTestName(const TestParamInfo<GenerationTestParam>& info)
{
    return info.param.toString();
}

static std::string DeriveTestName(const TestParamInfo<DeriveTestParam>& info)
{
    std::string name;

    name = std::get<0>(info.param).toString();
    name += "_";
    name += std::get<1>(info.param) ? "TLSv1_3" : "NotTLSv1_3";
    return name;
}

class GroupParamsGenerationTest : public TestWithParam<GenerationTestParam>
{
};

TEST_P(GroupParamsGenerationTest, GenerateKeyByParams)
{
    KeyPtr key;
    ASSERT_NO_THROW(key = GroupParams::generateKeyByParams(GetParam()));
    ASSERT_NE(key, nullptr);
}

TEST_P(GroupParamsGenerationTest, GenerateParamsThenKey)
{
    KeyPtr params;
    ASSERT_NO_THROW(params = GroupParams::generateParams(GetParam()));
    ASSERT_NE(params, nullptr);
    ASSERT_NO_THROW(params = GroupParams::generateKeyByParams(params));
}

INSTANTIATE_TEST_SUITE_P(ECDH, GroupParamsGenerationTest, ValuesIn(GroupParams::getSupported()), GenerationTestName);

class GroupParamsDeriveTest : public TestWithParam<DeriveTestParam>
{
};

TEST_P(GroupParamsDeriveTest, DeriveSharedKey)
{
    KeyPtr clientKey;
    KeyPtr serverKey;

    const auto& params = GetParam();

    ASSERT_NO_THROW(clientKey = GroupParams::generateKeyByParams(std::get<0>(params)));
    ASSERT_NO_THROW(serverKey = GroupParams::generateKeyByParams(std::get<0>(params)));

    std::vector<uint8_t> sharedKeyA;
    std::vector<uint8_t> sharedKeyB;
    ASSERT_NO_THROW(sharedKeyA = GroupParams::deriveSecret(clientKey, serverKey, std::get<1>(params)));
    ASSERT_NO_THROW(sharedKeyB = GroupParams::deriveSecret(serverKey, clientKey, std::get<1>(params)));

    ASSERT_EQ(sharedKeyA, sharedKeyB);
}

INSTANTIATE_TEST_SUITE_P(ECDH, GroupParamsDeriveTest, Combine(ValuesIn(GroupParams::getSupported()), Bool()), DeriveTestName);
