#include <gtest/gtest.h>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::crypto;
using namespace testing;

class GroupParamsTest : public TestWithParam<GroupParams>
{
};

TEST_P(GroupParamsTest, GenerateKeyByParams)
{
    KeyPtr key;
    ASSERT_NO_THROW(key = GroupParams::generateKeyByParams(GetParam()));
    ASSERT_NE(key, nullptr);
}

TEST_P(GroupParamsTest, GenerateParamsThenKey)
{
    KeyPtr params;
    ASSERT_NO_THROW(params = GroupParams::generateParams(GetParam()));
    ASSERT_NE(params, nullptr);
    ASSERT_NO_THROW(params = GroupParams::generateKeyByParams(params));
}

INSTANTIATE_TEST_CASE_P(EC, GroupParamsTest, ValuesIn(GroupParams::getSupported()));
