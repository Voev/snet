#include <gtest/gtest.h>
#include <snet/layers.hpp>

using namespace snet::layers;

TEST(VariableHeaderTest, EthernetWithoutVlan)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto eth = builder.eth();
    eth.set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(static_cast<uint16_t>(EtherType::IP)));
    builder.advance(eth.build());

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header));

    auto* eth_header = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth_header, nullptr);
    EXPECT_EQ(MacAddress(eth_header->dstMac), dst);
    EXPECT_EQ(MacAddress(eth_header->srcMac), src);
    EXPECT_EQ(casket::be_to_host(eth_header->etherType), static_cast<uint16_t>(EtherType::IP));
}

TEST(VariableHeaderTest, EthernetWithVlan)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // VLAN: etherType = 0x8100
    auto eth = builder.eth();
    eth.set(&ethernet_header::dstMac, dst)
       .set(&ethernet_header::srcMac, src)
       .set(&ethernet_header::etherType, casket::host_to_be(static_cast<uint16_t>(EtherType::VLAN)));
    builder.advance(eth.build());

    // Проверяем размер (14 + 4 = 18)
    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 4);
    EXPECT_EQ(builder.offset(), 18);

    // Проверяем данные
    auto* eth_header = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth_header, nullptr);
    EXPECT_EQ(std::memcmp(eth_header->dstMac, dst, 6), 0);
    EXPECT_EQ(std::memcmp(eth_header->srcMac, src, 6), 0);
    EXPECT_EQ(casket::be_to_host(eth_header->etherType), static_cast<uint16_t>(EtherType::VLAN));
}

/*
TEST(VariableHeaderTest, EthernetWithVlan)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // VLAN: type = 0x8100
    builder.eth()
           .set(&ethernet_header::dst, dst)
           .set(&ethernet_header::src, src)
           .set(&ethernet_header::type, htobe16(0x8100))
           .build();

    // Проверяем размер (14 + 4 = 18)
    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 4);
    EXPECT_EQ(builder.offset(), 18);

    // Проверяем данные
    auto* eth = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(be16toh(eth->type), 0x8100);
}

// ============================================================================
// 2. Тесты для IPv4 с переменной длиной
// ============================================================================

TEST(VariableHeaderTest, IPv4WithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    // Ethernet
    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 без опций (ihl = 5)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 5)   // 20 байт
           .set(&IPv4Header::tos, 0)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // Проверяем размер
    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20);
    EXPECT_EQ(builder.offset(), 14 + 20);

    auto* ip = reinterpret_cast<IPv4Header*>(builder.buffer() + sizeof(ethernet_header));
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->version, 4);
    EXPECT_EQ(ip->ihl, 5);
    EXPECT_EQ(ip->saddr, src_ip);
    EXPECT_EQ(ip->daddr, dst_ip);
}

TEST(VariableHeaderTest, IPv4WithOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 с опциями (ihl = 6 -> 24 байта)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)   // 24 байта
           .set(&IPv4Header::tos, 0)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // Проверяем размер (14 + 24)
    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 24);
    EXPECT_EQ(builder.offset(), 14 + 24);

    auto* ip = reinterpret_cast<IPv4Header*>(builder.buffer() + sizeof(ethernet_header));
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->ihl, 6);
}

TEST(VariableHeaderTest, IPv4WithMaxOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 с максимальными опциями (ihl = 15 -> 60 байт)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 15)  // 60 байт
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 60);
    EXPECT_EQ(builder.offset(), 14 + 60);
}

// ============================================================================
// 3. Тесты для TCP с переменной длиной
// ============================================================================

TEST(VariableHeaderTest, TCPWithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 5)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP без опций (doff = 5 -> 20 байт)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 5)   // 20 байт
           .set(&TCPHeader::syn, 1)
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20 + 20);
    EXPECT_EQ(builder.offset(), 14 + 20 + 20);
}

TEST(VariableHeaderTest, TCPWithOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 5)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с опциями (doff = 10 -> 40 байт)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)  // 40 байт
           .set(&TCPHeader::syn, 1)
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20 + 40);
    EXPECT_EQ(builder.offset(), 14 + 20 + 40);

    auto* tcp = reinterpret_cast<TCPHeader*>(
        builder.buffer() + sizeof(ethernet_header) + 20
    );
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->doff, 10);
}

TEST(VariableHeaderTest, TCPWithMaxOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 5)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с максимальными опциями (doff = 15 -> 60 байт)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 15)  // 60 байт
           .set(&TCPHeader::syn, 1)
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20 + 60);
    EXPECT_EQ(builder.offset(), 14 + 20 + 60);
}

// ============================================================================
// 4. Тесты для полноценных пакетов с переменной длиной
// ============================================================================

TEST(VariableHeaderTest, FullPacketWithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    // Ethernet (14)
    builder.eth()
           .set(&ethernet_header::dst, dst)
           .set(&ethernet_header::src, src)
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 без опций (20)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 5)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP без опций (20)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 5)
           .set(&TCPHeader::syn, 1)
           .build();

    // Payload
    const char* payload = "Hello, World!";
    builder.payload(payload, std::strlen(payload));

    auto* result = builder.build();
    ASSERT_NE(result, nullptr);

    // Проверяем общий размер
    size_t expected = 14 + 20 + 20 + std::strlen(payload);
    EXPECT_EQ(builder.offset(), expected);
    EXPECT_EQ(pkt.getLen(), expected);

    // Проверяем через Packet viewer
    auto* viewer = pkt.asPacket();
    auto* ip = viewer->getHeader<IPv4Header>(IPv4);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->getSrcIP(), src_ip);
    EXPECT_EQ(ip->getDstIP(), dst_ip);

    auto* tcp = viewer->getHeader<TCPHeader>(TCP);
    ASSERT_NE(tcp, nullptr);
    EXPECT_TRUE(tcp->isSyn());
}

TEST(VariableHeaderTest, FullPacketWithAllOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    // Ethernet без VLAN (14)
    builder.eth()
           .set(&ethernet_header::dst, dst)
           .set(&ethernet_header::src, src)
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 с опциями (24)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)   // 24 байта
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с опциями (40)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)  // 40 байт
           .set(&TCPHeader::syn, 1)
           .build();

    // Payload
    const char* payload = "Hello, World!";
    builder.payload(payload, std::strlen(payload));

    auto* result = builder.build();
    ASSERT_NE(result, nullptr);

    // Проверяем общий размер
    size_t expected = 14 + 24 + 40 + std::strlen(payload);
    EXPECT_EQ(builder.offset(), expected);
    EXPECT_EQ(pkt.getLen(), expected);

    // Проверяем через Packet viewer
    auto* viewer = pkt.asPacket();
    auto* ip = viewer->getHeader<IPv4Header>(IPv4);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->getIhl(), 6);

    auto* tcp = viewer->getHeader<TCPHeader>(TCP);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->getDoff(), 10);
    EXPECT_TRUE(tcp->isSyn());
}

TEST(VariableHeaderTest, FullPacketWithVlanAndOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    // Ethernet с VLAN (18)
    builder.eth()
           .set(&ethernet_header::dst, dst)
           .set(&ethernet_header::src, src)
           .set(&ethernet_header::type, htobe16(0x8100))  // VLAN
           .build();

    // IPv4 с опциями (24)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с опциями (40)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)
           .set(&TCPHeader::syn, 1)
           .build();

    const char* payload = "VLAN packet!";
    builder.payload(payload, std::strlen(payload));

    auto* result = builder.build();
    ASSERT_NE(result, nullptr);

    // Проверяем общий размер
    size_t expected = 18 + 24 + 40 + std::strlen(payload);
    EXPECT_EQ(builder.offset(), expected);
    EXPECT_EQ(pkt.getLen(), expected);

    // Проверяем Ethernet
    auto* eth = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(be16toh(eth->type), 0x8100);
}

// ============================================================================
// 5. Тесты для автоматического обновления checksum с переменной длиной
// ============================================================================

TEST(VariableHeaderTest, ChecksumWithVariableLength)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 с опциями (24)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с опциями (40)
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)
           .set(&TCPHeader::syn, 1)
           .build();

    builder.payload("Hello, World!");

    // До build() checksum = 0
    auto* ip = reinterpret_cast<IPv4Header*>(builder.buffer() + sizeof(ethernet_header));
    auto* tcp = reinterpret_cast<TCPHeader*>(
        builder.buffer() + sizeof(ethernet_header) + (ip->ihl * 4)
    );
    EXPECT_EQ(ip->check, 0);
    EXPECT_EQ(tcp->check, 0);

    // После build() checksum вычислены
    auto* result = builder.build();
    ASSERT_NE(result, nullptr);

    EXPECT_NE(ip->check, 0);
    EXPECT_NE(tcp->check, 0);
}

TEST(VariableHeaderTest, ChecksumNotRecalculated)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)
           .set(&TCPHeader::syn, 1)
           .build();

    builder.payload("Hello, World!");

    auto* result1 = builder.build();
    ASSERT_NE(result1, nullptr);

    auto* ip = reinterpret_cast<IPv4Header*>(builder.buffer() + sizeof(ethernet_header));
    auto* tcp = reinterpret_cast<TCPHeader*>(
        builder.buffer() + sizeof(ethernet_header) + (ip->ihl * 4)
    );

    uint16_t ip_checksum1 = ip->check;
    uint16_t tcp_checksum1 = tcp->check;

    // Второй build без изменений
    auto* result2 = builder.build();
    ASSERT_NE(result2, nullptr);

    EXPECT_EQ(ip->check, ip_checksum1);
    EXPECT_EQ(tcp->check, tcp_checksum1);
}

// ============================================================================
// 6. Тесты для модификации после build
// ============================================================================

TEST(VariableHeaderTest, ModifyPacketAfterBuild)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)
           .set(&TCPHeader::syn, 1)
           .build();

    auto* result1 = builder.build();
    ASSERT_NE(result1, nullptr);

    auto* ip = reinterpret_cast<IPv4Header*>(builder.buffer() + sizeof(ethernet_header));
    uint16_t old_checksum = ip->check;

    // Меняем IP адрес
    uint32_t new_ip = inet_addr("192.168.1.11");
    ip->saddr = new_ip;

    // Снова строим
    auto* result2 = builder.build();
    ASSERT_NE(result2, nullptr);

    EXPECT_NE(ip->check, old_checksum);
    EXPECT_EQ(ip->saddr, new_ip);
}

// ============================================================================
// 7. Тесты на безопасность
// ============================================================================

TEST(VariableHeaderTest, NoBufferOverflow)
{
    InMemoryPacket pkt(64); // Маленький буфер
    PacketBuilder<InMemoryPacket> builder(&pkt);

    uint32_t src_ip = inet_addr("192.168.1.10");
    uint32_t dst_ip = inet_addr("10.0.0.5");

    builder.eth()
           .set(&ethernet_header::type, htobe16(ETHERTYPE_IP))
           .build();

    // IPv4 с опциями (24)
    builder.ipv4()
           .set(&IPv4Header::version, 4)
           .set(&IPv4Header::ihl, 6)
           .set(&IPv4Header::ttl, 64)
           .set(&IPv4Header::protocol, IPPROTO_TCP)
           .set(&IPv4Header::saddr, src_ip)
           .set(&IPv4Header::daddr, dst_ip)
           .build();

    // TCP с опциями (40) - уже должно быть переполнение
    builder.tcp()
           .set(&TCPHeader::source, htobe16(12345))
           .set(&TCPHeader::dest, htobe16(80))
           .set(&TCPHeader::seq, htobe32(0x100000))
           .set(&TCPHeader::doff, 10)
           .set(&TCPHeader::syn, 1)
           .build();

    // Попытка добавить payload
    const char* data = "This is too long!";
    builder.payload(data, std::strlen(data));

    auto* result = builder.build();

    // Пакет должен быть собран, но не должен выйти за пределы
    EXPECT_NE(result, nullptr);
    EXPECT_LE(builder.offset(), 64);
}
*/