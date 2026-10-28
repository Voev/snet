#include <gtest/gtest.h>
#include <snet/tls/exts/encrypt_then_mac.hpp>

using namespace snet;
using namespace snet::tls;

class EncryptThenMACTest : public ::testing::Test
{
};

TEST_F(EncryptThenMACTest, EmptyInputParses)
{
    EncryptThenMAC etm;
    ASSERT_EQ(etm.deserialize(Side::Client, {}), utils::DecodeError::None);
    ASSERT_EQ(etm.deserialize(Side::Server, {}), utils::DecodeError::None);
}

TEST_F(EncryptThenMACTest, NonEmptyInputFails)
{
    const uint8_t dummy = 0;
    nonstd::span<const uint8_t> span(&dummy, 1);

    EncryptThenMAC etm;
    ASSERT_EQ(etm.deserialize(Side::Client, span), utils::DecodeError::LengthOutOfRange);
    ASSERT_EQ(etm.deserialize(Side::Server, span), utils::DecodeError::LengthOutOfRange);
}

TEST_F(EncryptThenMACTest, StaticType)
{
    ASSERT_EQ(EncryptThenMAC::staticType(), ExtensionCode::EncryptThenMac);
}

TEST_F(EncryptThenMACTest, EmptyReturnsFalse)
{
    EncryptThenMAC etm;
    ASSERT_FALSE(etm.empty());
}

TEST_F(EncryptThenMACTest, SerializationWritesNothing)
{
    std::vector<uint8_t> buffer(10, 0xAA);
    std::vector<uint8_t> buffer2(10, 0xAA);

    EncryptThenMAC etm;
    const std::size_t written = etm.serialize(Side::Client, buffer);
    ASSERT_EQ(written, 0);
    buffer.resize(written);

    EncryptThenMAC etm2;
    ASSERT_EQ(etm2.deserialize(Side::Server, {}), utils::DecodeError::None);

    const std::size_t written2 = etm2.serialize(Side::Server, buffer2);
    ASSERT_EQ(written2, 0);
    buffer2.resize(written2);

    ASSERT_EQ(buffer, buffer2);
}