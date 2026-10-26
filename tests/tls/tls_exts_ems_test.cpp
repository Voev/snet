#include <gtest/gtest.h>
#include <snet/tls/exts/extended_master_secret.hpp>

using namespace snet;
using namespace snet::tls;

class ExtendedMasterSecretTest : public ::testing::Test
{
};

TEST_F(ExtendedMasterSecretTest, EmptyInputParses)
{
    ExtendedMasterSecret ems;
    ASSERT_EQ(ems.deserialize(Side::Client, {}), utils::DecodeError::None);
    ASSERT_EQ(ems.deserialize(Side::Server, {}), utils::DecodeError::None);
}

TEST_F(ExtendedMasterSecretTest, NonEmptyInputFails)
{
    const uint8_t dummy = 0;
    nonstd::span<const uint8_t> span(&dummy, 1);

    ExtendedMasterSecret ems;
    ASSERT_EQ(ems.deserialize(Side::Client, span), utils::DecodeError::LengthOutOfRange);
    ASSERT_EQ(ems.deserialize(Side::Server, span), utils::DecodeError::LengthOutOfRange);
}

TEST_F(ExtendedMasterSecretTest, StaticType)
{
    ASSERT_EQ(ExtendedMasterSecret::staticType(), ExtensionCode::ExtendedMasterSecret);
}

TEST_F(ExtendedMasterSecretTest, EmptyReturnsFalse)
{
    ExtendedMasterSecret ems;
    ASSERT_FALSE(ems.empty());
}

TEST_F(ExtendedMasterSecretTest, SerializationWritesNothing)
{
    std::vector<uint8_t> buffer(10, 0xAA);
    std::vector<uint8_t> buffer2(10, 0xAA);

    ExtendedMasterSecret ems;
    const std::size_t written = ems.serialize(Side::Client, buffer);
    ASSERT_EQ(written, 0);
    buffer.resize(written);

    ExtendedMasterSecret ems2;
    ASSERT_EQ(ems2.deserialize(Side::Server, {}), utils::DecodeError::None);

    const std::size_t written2 = ems2.serialize(Side::Server, buffer2);
    ASSERT_EQ(written2, 0);
    buffer2.resize(written2);

    ASSERT_EQ(buffer, buffer2);
}