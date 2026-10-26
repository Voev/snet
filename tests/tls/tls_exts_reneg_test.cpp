#include <gtest/gtest.h>
#include <snet/tls/exts/reneg_extension.hpp>

using namespace snet;
using namespace snet::tls;

class RenegotiationExtensionTest : public ::testing::Test
{
};

TEST_F(RenegotiationExtensionTest, StaticType)
{
    ASSERT_EQ(RenegotiationExtension::staticType(), ExtensionCode::SafeRenegotiation);
}

TEST_F(RenegotiationExtensionTest, EmptyReturnsFalse)
{
    RenegotiationExtension ext;
    ASSERT_FALSE(ext.empty());
}

TEST_F(RenegotiationExtensionTest, DefaultHasNoData)
{
    RenegotiationExtension ext;
    ASSERT_TRUE(ext.getRenegInfo().empty());
}

TEST_F(RenegotiationExtensionTest, ConstructorFromData)
{
    std::vector<uint8_t> renegData{0x01};

    RenegotiationExtension ext(std::move(renegData));
    const auto info = ext.getRenegInfo();

    ASSERT_EQ(info.size(), 1u);
    ASSERT_EQ(info[0], 0x01);
}

TEST_F(RenegotiationExtensionTest, DeserializeEmpty)
{
    const uint8_t input[] = {0x00};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::None);
    ASSERT_TRUE(ext.getRenegInfo().empty());
}

TEST_F(RenegotiationExtensionTest, DeserializeData)
{
    const uint8_t input[] = {0x02, 0xAA, 0xBB};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::None);

    const auto info = ext.getRenegInfo();
    ASSERT_EQ(info.size(), 2u);
    ASSERT_EQ(info[0], 0xAA);
    ASSERT_EQ(info[1], 0xBB);
}

TEST_F(RenegotiationExtensionTest, DeserializeFailsOnEmptyInput)
{
    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, {}), utils::DecodeError::NotEnoughBytes);
}

TEST_F(RenegotiationExtensionTest, DeserializeFailsOnShortData)
{
    const uint8_t input[] = {0x02, 0xAA};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::NotEnoughBytes);
    ASSERT_TRUE(ext.getRenegInfo().empty());
}

TEST_F(RenegotiationExtensionTest, DeserializeFailsOnTrailingBytes)
{
    const uint8_t input[] = {0x01, 0xAA, 0xBB};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::TrailingBytes);
    ASSERT_TRUE(ext.getRenegInfo().empty());
}

TEST_F(RenegotiationExtensionTest, SerializeEmpty)
{
    const uint8_t input[] = {0x00};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::None);

    std::vector<uint8_t> output(8, 0xCC);
    const std::size_t written = ext.serialize(Side::Client, output);

    ASSERT_EQ(written, 1u);
    ASSERT_EQ(output[0], 0x00);
}

TEST_F(RenegotiationExtensionTest, SerializeData)
{
    const uint8_t input[] = {0x02, 0xAA, 0xBB};

    RenegotiationExtension ext;
    ASSERT_EQ(ext.deserialize(Side::Client, input), utils::DecodeError::None);

    std::vector<uint8_t> output(8, 0xCC);
    const std::size_t written = ext.serialize(Side::Client, output);
    ASSERT_EQ(written, 3u);
    output.resize(written);

    RenegotiationExtension ext2;
    ASSERT_EQ(ext2.deserialize(Side::Client, output), utils::DecodeError::None);
    ASSERT_EQ(ext.getRenegInfo().size(), ext2.getRenegInfo().size());
    for (std::size_t i = 0; i < ext.getRenegInfo().size(); ++i)
    {
        ASSERT_EQ(ext.getRenegInfo()[i], ext2.getRenegInfo()[i]);
    }
}

TEST_F(RenegotiationExtensionTest, SerializeFailsOnTinyBuffer)
{
    RenegotiationExtension ext(std::vector<uint8_t>{0xAA});

    uint8_t output[1]{};
    ASSERT_EQ(ext.serialize(Side::Client, output), kSerializationFailed);
}

TEST_F(RenegotiationExtensionTest, SerializeFailsOnTooLongBody)
{
    std::vector<uint8_t> data(256, 0xAA);
    RenegotiationExtension ext(std::move(data));

    std::vector<uint8_t> output(300, 0);
    ASSERT_EQ(ext.serialize(Side::Client, output), kSerializationFailed);
}