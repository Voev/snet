#include <gtest/gtest.h>
#include <snet/tls/exts/supported_point_formats.hpp>

using namespace snet;
using namespace snet::tls;

class SupportedPointFormatsTest : public ::testing::Test
{
};

TEST_F(SupportedPointFormatsTest, StaticType)
{
    ASSERT_EQ(SupportedPointFormats::staticType(), ExtensionCode::ECPointFormats);
}

TEST_F(SupportedPointFormatsTest, DefaultIsEmpty)
{
    SupportedPointFormats formats;
    ASSERT_TRUE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, EmptyReturnsFalseWhenFormatsPresent)
{
    SupportedPointFormats formats({ECPointFormat::Uncompressed});
    ASSERT_FALSE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, SerializeProducesCorrectOutput)
{
    SupportedPointFormats formats({ECPointFormat::Uncompressed});

    uint8_t buffer[32]{};
    const std::size_t written = formats.serialize(Side::Client, buffer);

    ASSERT_EQ(written, 2u);
    ASSERT_EQ(buffer[0], 1);
    ASSERT_EQ(buffer[1], 0);
}

TEST_F(SupportedPointFormatsTest, SerializeFailsOnTinyBuffer)
{
    SupportedPointFormats formats({ECPointFormat::Uncompressed});

    uint8_t buffer[1]{};
    ASSERT_EQ(formats.serialize(Side::Client, buffer), kSerializationFailed);
}

TEST_F(SupportedPointFormatsTest, DeserializeHandlesValidInput)
{
    const uint8_t serialized[] = {3, 0, 1, 2};

    SupportedPointFormats formats;
    ASSERT_EQ(formats.deserialize(Side::Server, serialized), utils::DecodeError::None);
    ASSERT_EQ(formats.getFormats().size(), 3u);
    ASSERT_EQ(formats.getFormats()[0], ECPointFormat::Uncompressed);
    ASSERT_EQ(formats.getFormats()[1], ECPointFormat::AnsiX962CompressedPrime);
    ASSERT_EQ(formats.getFormats()[2], ECPointFormat::AnsiX962CompressedChar2);
}

TEST_F(SupportedPointFormatsTest, DeserializeFailsOnInvalidFormat)
{
    const uint8_t serialized[] = {1, 3};

    SupportedPointFormats formats;
    ASSERT_EQ(formats.deserialize(Side::Client, serialized), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, DeserializeFailsOnLengthMismatch)
{
    const uint8_t serialized[] = {2, 0};

    SupportedPointFormats formats;
    ASSERT_EQ(formats.deserialize(Side::Client, serialized), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, DeserializeFailsOnEmptyInput)
{
    SupportedPointFormats formats;
    ASSERT_EQ(formats.deserialize(Side::Client, {}), utils::DecodeError::NotEnoughBytes);
    ASSERT_TRUE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, DeserializeFailsOnTrailingBytes)
{
    const uint8_t serialized[] = {1, 0, 0};

    SupportedPointFormats formats;
    ASSERT_EQ(formats.deserialize(Side::Client, serialized), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(formats.empty());
}

TEST_F(SupportedPointFormatsTest, RoundTripSerialization)
{
    SupportedPointFormats original({
        ECPointFormat::Uncompressed,
        ECPointFormat::AnsiX962CompressedChar2,
        ECPointFormat::AnsiX962CompressedPrime
    });

    uint8_t buffer[32]{};
    const std::size_t written = original.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_EQ(written, 4u);

    SupportedPointFormats deserialized;
    ASSERT_EQ(deserialized.deserialize(Side::Server, {buffer, written}), utils::DecodeError::None);

    const auto a = original.getFormats();
    const auto b = deserialized.getFormats();
    ASSERT_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        ASSERT_EQ(a[i], b[i]);
    }
}