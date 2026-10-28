#include <gtest/gtest.h>
#include <snet/tls/exts/supported_versions.hpp>

using namespace snet;
using namespace snet::tls;

class SupportedVersionsTest : public ::testing::Test
{
};

TEST_F(SupportedVersionsTest, StaticType)
{
    ASSERT_EQ(SupportedVersions::staticType(), ExtensionCode::SupportedVersions);
}

TEST_F(SupportedVersionsTest, DefaultIsEmpty)
{
    SupportedVersions sv;
    ASSERT_TRUE(sv.empty());
    ASSERT_EQ(sv.versions().size(), 0u);
}

TEST_F(SupportedVersionsTest, ConstructionWithSingleVersion)
{
    SupportedVersions sv(ProtocolVersion::TLSv1_3);
    ASSERT_FALSE(sv.empty());
    ASSERT_EQ(sv.versions().size(), 1u);
    ASSERT_EQ(sv.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, ClientSideDeserialize)
{
    const uint8_t data[] = {0x04, 0x03, 0x03, 0x03, 0x04};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Client, data), utils::DecodeError::None);
    ASSERT_EQ(sv.versions().size(), 2u);
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_2));
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_3));
}

TEST_F(SupportedVersionsTest, ServerSideDeserialize)
{
    const uint8_t data[] = {0x03, 0x04};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Server, data), utils::DecodeError::None);
    ASSERT_EQ(sv.versions().size(), 1u);
    ASSERT_EQ(sv.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, ServerSideFailsOnTrailingBytes)
{
    const uint8_t data[] = {0x03, 0x04, 0x05};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Server, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sv.empty());
}

TEST_F(SupportedVersionsTest, ServerSideFailsOnShortInput)
{
    const uint8_t data[] = {0x03};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Server, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sv.empty());
}

TEST_F(SupportedVersionsTest, ClientSideFailsOnZeroLength)
{
    const uint8_t data[] = {0x00};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Client, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sv.empty());
}

TEST_F(SupportedVersionsTest, ClientSideFailsOnOddLength)
{
    const uint8_t data[] = {0x03, 0x03, 0x04, 0x00};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Client, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sv.empty());
}

TEST_F(SupportedVersionsTest, ClientSideFailsOnLengthMismatch)
{
    const uint8_t data[] = {0x04, 0x03, 0x03};

    SupportedVersions sv;
    ASSERT_EQ(sv.deserialize(Side::Client, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sv.empty());
}

TEST_F(SupportedVersionsTest, ClientSerialization)
{
    const std::vector<ProtocolVersion> versions = {
        ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3
    };
    SupportedVersions sv(versions);

    std::vector<uint8_t> buffer(16);
    const std::size_t written = sv.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_EQ(written, 5u);
    buffer.resize(written);

    SupportedVersions sv2;
    ASSERT_EQ(sv2.deserialize(Side::Client, buffer), utils::DecodeError::None);
    ASSERT_EQ(sv2.versions().size(), versions.size());
    for (std::size_t i = 0; i < versions.size(); ++i)
    {
        ASSERT_EQ(sv2.versions()[i], versions[i]);
    }
}

TEST_F(SupportedVersionsTest, ServerSerialization)
{
    SupportedVersions sv(ProtocolVersion::TLSv1_3);

    std::vector<uint8_t> buffer(16);
    const std::size_t written = sv.serialize(Side::Server, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_EQ(written, 2u);
    buffer.resize(written);

    SupportedVersions sv2;
    ASSERT_EQ(sv2.deserialize(Side::Server, buffer), utils::DecodeError::None);
    ASSERT_EQ(sv2.versions().size(), 1u);
    ASSERT_EQ(sv2.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, ServerSerializationFailsOnMultipleVersions)
{
    const std::vector<ProtocolVersion> versions = {
        ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3
    };
    SupportedVersions sv(versions);

    std::vector<uint8_t> buffer(16);
    ASSERT_EQ(sv.serialize(Side::Server, buffer), kSerializationFailed);
}

TEST_F(SupportedVersionsTest, ClientSerializationFailsOnTinyBuffer)
{
    const std::vector<ProtocolVersion> versions = {
        ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3
    };
    SupportedVersions sv(versions);

    std::vector<uint8_t> buffer(3);
    ASSERT_EQ(sv.serialize(Side::Client, buffer), kSerializationFailed);
}

TEST_F(SupportedVersionsTest, SupportsMethod)
{
    const std::vector<ProtocolVersion> versions = {
        ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3
    };
    SupportedVersions sv(versions);

    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_2));
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_3));
    ASSERT_FALSE(sv.supports(ProtocolVersion::TLSv1_1));
}