#include <gtest/gtest.h>
#include <snet/tls/exts/record_size_limit.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket::utils;

class RecordSizeLimitTest : public ::testing::Test
{
};

TEST_F(RecordSizeLimitTest, ConstructorStoresLimitCorrectly)
{
    uint16_t limitValue = 1500;
    RecordSizeLimit limit(limitValue);
    EXPECT_EQ(limitValue, limit.limit());
}

TEST_F(RecordSizeLimitTest, SerializeProducesCorrectOutput)
{
    uint16_t limitValue = 1500;
    RecordSizeLimit limit(limitValue);
    uint8_t buffer[4];
    auto written = limit.serialize(Side::Client, buffer);

    EXPECT_EQ(2, written);
    EXPECT_EQ(limitValue >> 8, buffer[0]);
    EXPECT_EQ(limitValue & 0xFF, buffer[1]);
}

TEST_F(RecordSizeLimitTest, DeserializeHandlesValidInput)
{
    const uint8_t serialized[] = {0x05, 0xDC};
    RecordSizeLimit limit(Side::Server, serialized);

    EXPECT_EQ(1500, limit.limit());
}

TEST_F(RecordSizeLimitTest, DeserializeThrowsOnInvalidLength)
{
    const uint8_t serialized[] = {0x05};
    EXPECT_THROW(RecordSizeLimit limit(Side::Server, serialized), RuntimeError);
}

TEST_F(RecordSizeLimitTest, RoundTripSerialization)
{
    RecordSizeLimit original(16 * 1024);
    uint8_t buffer[4];
    auto written = original.serialize(Side::Client, buffer);

    RecordSizeLimit deserialized(Side::Server, {buffer, written});
    EXPECT_EQ(original.limit(), deserialized.limit());
}

TEST_F(RecordSizeLimitTest, HandlesMaximumLimitValue)
{
    uint16_t maxLimit = 65535;
    ASSERT_THROW(RecordSizeLimit limit(maxLimit), RuntimeError);
}