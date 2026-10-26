#include <gtest/gtest.h>
#include <snet/tls/exts/record_size_limit.hpp>

using namespace snet;
using namespace snet::tls;

class RecordSizeLimitTest : public ::testing::Test
{
};

TEST_F(RecordSizeLimitTest, StaticType)
{
    ASSERT_EQ(RecordSizeLimit::staticType(), ExtensionCode::RecordSizeLimit);
}

TEST_F(RecordSizeLimitTest, DefaultIsEmpty)
{
    RecordSizeLimit rsl;
    ASSERT_TRUE(rsl.empty());
    ASSERT_EQ(rsl.limit(), 0);
}

TEST_F(RecordSizeLimitTest, ConstructorStoresLimitCorrectly)
{
    RecordSizeLimit rsl(1500);
    ASSERT_FALSE(rsl.empty());
    ASSERT_EQ(rsl.limit(), 1500);
}

TEST_F(RecordSizeLimitTest, SerializeProducesCorrectOutput)
{
    RecordSizeLimit rsl(1500);
    uint8_t buffer[2]{};
    const std::size_t written = rsl.serialize(Side::Client, buffer);

    ASSERT_EQ(written, 2u);
    ASSERT_EQ(buffer[0], 1500 >> 8);
    ASSERT_EQ(buffer[1], 1500 & 0xFF);
}

TEST_F(RecordSizeLimitTest, SerializeFailsOnTinyBuffer)
{
    RecordSizeLimit rsl(1500);
    uint8_t buffer[1]{};
    ASSERT_EQ(rsl.serialize(Side::Client, buffer), kSerializationFailed);
}

TEST_F(RecordSizeLimitTest, DeserializeHandlesValidInput)
{
    const uint8_t serialized[] = {0x05, 0xDC};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Server, serialized), utils::DecodeError::None);
    ASSERT_EQ(rsl.limit(), 1500);
}

TEST_F(RecordSizeLimitTest, DeserializeFailsOnShortInput)
{
    const uint8_t serialized[] = {0x05};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Server, serialized), utils::DecodeError::NotEnoughBytes);
    ASSERT_TRUE(rsl.empty());
}

TEST_F(RecordSizeLimitTest, DeserializeFailsOnTrailingBytes)
{
    const uint8_t serialized[] = {0x05, 0xDC, 0x00};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Server, serialized), utils::DecodeError::TrailingBytes);
    ASSERT_TRUE(rsl.empty());
}

TEST_F(RecordSizeLimitTest, DeserializeRejectsTooSmallLimit)
{
    const uint8_t serialized[] = {0x00, 0x3F};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Server, serialized), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(rsl.empty());
}

TEST_F(RecordSizeLimitTest, DeserializeRejectsTooLargeLimitOnServer)
{
    const uint8_t serialized[] = {0x40, 0x02};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Server, serialized), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(rsl.empty());
}

TEST_F(RecordSizeLimitTest, DeserializeAcceptsLargeLimitOnClient)
{
    const uint8_t serialized[] = {0x40, 0x02};

    RecordSizeLimit rsl;
    ASSERT_EQ(rsl.deserialize(Side::Client, serialized), utils::DecodeError::None);
    ASSERT_EQ(rsl.limit(), 0x4002);
}

TEST_F(RecordSizeLimitTest, RoundTripSerialization)
{
    RecordSizeLimit original(16 * 1024);

    uint8_t buffer[2]{};
    const std::size_t written = original.serialize(Side::Client, buffer);
    ASSERT_EQ(written, 2u);

    RecordSizeLimit deserialized;
    ASSERT_EQ(deserialized.deserialize(Side::Client, {buffer, written}), utils::DecodeError::None);
    ASSERT_EQ(deserialized.limit(), original.limit());
}