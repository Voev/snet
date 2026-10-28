#include <gtest/gtest.h>
#include <snet/tls/exts/server_name_indication.hpp>

using namespace snet;
using namespace snet::tls;

class ServerNameIndicationTest : public ::testing::Test
{
};

TEST_F(ServerNameIndicationTest, StaticType)
{
    ASSERT_EQ(ServerNameIndicator::staticType(), ExtensionCode::ServerNameIndication);
}

TEST_F(ServerNameIndicationTest, EmptyReturnsFalse)
{
    ServerNameIndicator sni;
    ASSERT_FALSE(sni.empty());
}

TEST_F(ServerNameIndicationTest, ConstructorStoresHostname)
{
    ServerNameIndicator sni("example.com");
    ASSERT_EQ(sni.getHostname(), "example.com");
}

TEST_F(ServerNameIndicationTest, SerializeClient)
{
    ServerNameIndicator sni("example.com");
    std::vector<uint8_t> buffer(64);

    const std::size_t written = sni.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_EQ(written, 5u + 11u);
}

TEST_F(ServerNameIndicationTest, SerializeServer)
{
    ServerNameIndicator sni("example.com");
    std::vector<uint8_t> buffer(64);

    ASSERT_EQ(sni.serialize(Side::Server, buffer), kSerializationFailed);
}

TEST_F(ServerNameIndicationTest, SerializeFailsOnTinyBuffer)
{
    ServerNameIndicator sni("example.com");
    std::vector<uint8_t> buffer(4);

    ASSERT_EQ(sni.serialize(Side::Client, buffer), kSerializationFailed);
}

TEST_F(ServerNameIndicationTest, DeserializeFromData)
{
    const uint8_t data[] = {
        0x00, 0x0E,
        0x00, 0x00, 0x0B,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };

    ServerNameIndicator sni;
    ASSERT_EQ(sni.deserialize(Side::Client, data), utils::DecodeError::None);
    ASSERT_EQ(sni.getHostname(), "example.com");
}

TEST_F(ServerNameIndicationTest, DeserializeFromEmptyData)
{
    ServerNameIndicator sni;
    ASSERT_EQ(sni.deserialize(Side::Client, {}), utils::DecodeError::None);
    ASSERT_TRUE(sni.getHostname().empty());
}

TEST_F(ServerNameIndicationTest, SerializeDeserializeRoundtrip)
{
    ServerNameIndicator original("example.com");

    std::vector<uint8_t> buffer(64);
    const std::size_t written = original.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    buffer.resize(written);

    ServerNameIndicator deserialized;
    ASSERT_EQ(deserialized.deserialize(Side::Server, buffer), utils::DecodeError::None);
    ASSERT_EQ(deserialized.getHostname(), "example.com");
}

TEST_F(ServerNameIndicationTest, DeserializeFailsOnTruncatedNameList)
{
    const uint8_t data[] = {0x00, 0x00, 0x00};

    ServerNameIndicator sni;
    ASSERT_NE(sni.deserialize(Side::Server, data), utils::DecodeError::None);
    ASSERT_TRUE(sni.getHostname().empty());
}

TEST_F(ServerNameIndicationTest, DeserializeFailsOnMismatchedListLength)
{
    const uint8_t data[] = {0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00};

    ServerNameIndicator sni;
    ASSERT_EQ(sni.deserialize(Side::Server, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(sni.getHostname().empty());
}

TEST_F(ServerNameIndicationTest, DeserializeFailsOnTruncatedHostName)
{
    const uint8_t data[] = {0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 0x61};

    ServerNameIndicator sni;
    ASSERT_NE(sni.deserialize(Side::Server, data), utils::DecodeError::None);
    ASSERT_TRUE(sni.getHostname().empty());
}

TEST_F(ServerNameIndicationTest, DeserializeSkipsUnknownNameType)
{
    const uint8_t data[] = {
        0x00, 0x0D,
        0x01, 0x00, 0x02, 0xAA, 0xBB,
        0x00, 0x00, 0x05,
        'h', 'e', 'l', 'l', 'o'
    };

    ServerNameIndicator sni;
    ASSERT_EQ(sni.deserialize(Side::Client, data), utils::DecodeError::None);
    ASSERT_EQ(sni.getHostname(), "hello");
}