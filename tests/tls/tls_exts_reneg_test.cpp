#include <gtest/gtest.h>
#include <snet/tls/exts/reneg_extension.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket::utils;

class RenegotiationExtensionTest : public ::testing::Test
{
};

TEST_F(RenegotiationExtensionTest, RenegotiationInfo)
{
    std::vector<uint8_t> renegData{0x01};
    RenegotiationExtension ext(renegData);
    ASSERT_EQ(renegData, ext.getRenegInfo());
}

TEST_F(RenegotiationExtensionTest, SerializeEmpty)
{
    std::vector<uint8_t> input = {0x00};
    RenegotiationExtension ext(Side::Client, input);

    std::vector<uint8_t> output(10);
    size_t written = ext.serialize(Side::Client, output);
    output.resize(written);

    ASSERT_EQ(1, written);
    ASSERT_TRUE(ext.getRenegInfo().empty());
}

TEST_F(RenegotiationExtensionTest, SerializeData)
{
    std::vector<uint8_t> input = {0x02, 0xAA, 0xBB};
    RenegotiationExtension ext(Side::Client, input);

    std::vector<uint8_t> output(10, 0);
    size_t written = ext.serialize(Side::Client, output);
    output.resize(written);

    RenegotiationExtension ext2(Side::Client, output);

    ASSERT_EQ(ext.getRenegInfo(), ext2.getRenegInfo());
}

TEST_F(RenegotiationExtensionTest, ConstructorFromSpanInvalidLength)
{
    std::vector<uint8_t> input = {0x02, 0xAA};
    ASSERT_THROW(RenegotiationExtension ext(Side::Client, input), RuntimeError);
}

TEST_F(RenegotiationExtensionTest, ConstructorFromSpanTooLong)
{
    std::vector<uint8_t> input(258, 0);
    input[0] = 0xFF;
    input[1] = 0x01;

    ASSERT_THROW(RenegotiationExtension ext(Side::Client, input), RuntimeError);
}