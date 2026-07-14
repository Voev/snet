#include <gtest/gtest.h>
#include <snet/layers/in_memory_packet.hpp>

using namespace snet::layers;

TEST(InMemoryPacketTest, BasicOperations)
{
    // 1. Создание
    InMemoryPacket pkt(2048);
    EXPECT_EQ(pkt.getCapacity(), 2048);
    EXPECT_EQ(pkt.getLen(), 0);

    // 2. Установка данных
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    pkt.setData(data, sizeof(data));
    EXPECT_EQ(pkt.getLen(), 4);
    EXPECT_EQ(pkt.getData()[0], 0x01);
    EXPECT_EQ(pkt.getData()[3], 0x04);

    // 3. Packet viewer
    auto* viewer = pkt.asPacket();
    EXPECT_EQ(viewer->getDataLen(), 4);
    EXPECT_EQ(viewer->getData()[0], 0x01);
}

/*
TEST(InMemoryPacketTest, BuildSynPacket)
{
    InMemoryPacket pkt(2048);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    auto* result = buildSyn(&pkt, dst, src, inet_addr("192.168.1.10"), inet_addr("10.0.0.5"), 12345, 80);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(pkt.getLen(), 54); // 14 + 20 + 20

    // Проверяем заголовки через Packet viewer
    auto* viewer = pkt.asPacket();
    auto ip = viewer->getHeader<IPv4Header>(IPv4);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip.getSrcIP(), inet_addr("192.168.1.10"));
    EXPECT_EQ(ip->getDstIP(), inet_addr("10.0.0.5"));

    auto* tcp = viewer->getHeader<TCPHeader>(TCP);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->getSrcPort(), 12345);
    EXPECT_EQ(tcp->getDstPort(), 80);
    EXPECT_TRUE(tcp->isSyn());
}*/

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