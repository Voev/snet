#include <gtest/gtest.h>
#include <snet/layers/packet.hpp>

using namespace snet::layers;

TEST(PacketTest, SetGetData)
{
    std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04, 0x05};

    Packet packet;
    bool result = packet.setRawData(testData, LINKTYPE_ETHERNET, -1);

    EXPECT_TRUE(result);
    EXPECT_EQ(packet.getDataLen(), testData.size());
    EXPECT_NE(packet.getData(), nullptr);
    EXPECT_EQ(memcmp(packet.getData(), testData.data(), testData.size()), 0);
}
