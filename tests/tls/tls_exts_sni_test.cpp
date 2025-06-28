#include <gtest/gtest.h>
#include <snet/tls/exts/server_name_indication.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket::utils;

class ServerNameIndicationTest : public ::testing::Test
{
};

TEST_F(ServerNameIndicationTest, GetHostname)
{
    ServerNameIndicator sni("example.com");
    ASSERT_EQ("example.com", sni.getHostname());
}

TEST_F(ServerNameIndicationTest, SerializeClient)
{
    ServerNameIndicator sni("example.com");
    std::vector<uint8_t> buffer(100);
    size_t written = sni.serialize(Side::Client, buffer);

    ASSERT_GT(written, 0);
}

TEST_F(ServerNameIndicationTest, SerializeServer)
{
    ServerNameIndicator sni("example.com");
    std::vector<uint8_t> buffer(100);
    size_t written = sni.serialize(Side::Server, buffer);

    ASSERT_EQ(written, 0);
}

TEST_F(ServerNameIndicationTest, ConstructorFromData)
{
    std::vector<uint8_t> data = {0x00, 0x0E, 0x00, 0x00, 0x0B, 0x65, 0x78, 0x61,
                                 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D};
    ServerNameIndicator sni(Side::Client, data);

    ASSERT_EQ("example.com", sni.getHostname());
}

TEST_F(ServerNameIndicationTest, ConstructorFromEmptyData)
{
    std::vector<uint8_t> data;
    ServerNameIndicator sni(Side::Client, data);

    ASSERT_TRUE(sni.getHostname().empty());
}

TEST_F(ServerNameIndicationTest, SerializeDeserializeRoundtrip)
{
    const std::string originalHostname = "example.com";
    ServerNameIndicator originalSni(originalHostname);

    std::vector<uint8_t> buffer(256);
    size_t serializedSize = originalSni.serialize(Side::Client, buffer);
    ASSERT_GT(serializedSize, 0);

    cpp::span<const uint8_t> serializedData(buffer.data(), serializedSize);
    ServerNameIndicator deserializedSni(Side::Server, serializedData);

    ASSERT_EQ(originalHostname, deserializedSni.getHostname());
}

TEST_F(ServerNameIndicationTest, DeserializeInvalidData)
{
    std::vector<uint8_t> invalidData1 = {0x00, 0x00, 0x00};
    EXPECT_THROW({ ServerNameIndicator sni(Side::Server, invalidData1); }, RuntimeError);

    std::vector<uint8_t> invalidData2 = {0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00};
    EXPECT_THROW({ ServerNameIndicator sni(Side::Server, invalidData2); }, RuntimeError);

    std::vector<uint8_t> invalidData3 = {0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 0x61};
    EXPECT_THROW({ ServerNameIndicator sni(Side::Server, invalidData3); }, RuntimeError);
}