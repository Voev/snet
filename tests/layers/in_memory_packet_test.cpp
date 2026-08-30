#include <gtest/gtest.h>
#include <snet/layers/in_memory_packet.hpp>

using namespace snet::layers;

TEST(InMemoryPacketTest, BasicOperations)
{
    InMemoryPacket pkt(2048);
    EXPECT_EQ(pkt.getCapacity(), 2048);
    EXPECT_EQ(pkt.getLen(), 0);

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    pkt.setData(data, sizeof(data));
    EXPECT_EQ(pkt.getLen(), 4);
    EXPECT_EQ(pkt.getData()[0], 0x01);
    EXPECT_EQ(pkt.getData()[3], 0x04);

    auto* viewer = pkt.asPacket();
    EXPECT_EQ(viewer->getDataLen(), 4);
    EXPECT_EQ(viewer->getData()[0], 0x01);
}

TEST(InMemoryPacketTest, MoveAndClone)
{
    InMemoryPacket pkt1(1024);
    uint8_t data[] = {0x01, 0x02, 0x03};
    pkt1.setData(data, sizeof(data));

    // Move
    InMemoryPacket pkt2(std::move(pkt1));
    EXPECT_EQ(pkt2.getLen(), 3);
    EXPECT_EQ(pkt2.getData()[0], 0x01);
    EXPECT_EQ(pkt1.getLen(), 0); // moved-from

    // Clone
    auto pkt3 = pkt2.clone();
    EXPECT_EQ(pkt3.getLen(), 3);
    EXPECT_EQ(pkt3.getData()[0], 0x01);
    // pkt2 unchanged
    EXPECT_EQ(pkt2.getLen(), 3);
}