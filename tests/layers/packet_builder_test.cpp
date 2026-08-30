#include <gtest/gtest.h>
#include <snet/layers.hpp>
#include <snet/utils/to_underlying.hpp>

using namespace snet::layers;

TEST(PacketBuilderTest, EthernetWithoutVlan)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto eth = builder.eth();
    eth.set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(static_cast<uint16_t>(EtherType::IP)))
       .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header));

    auto* eth_header = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth_header, nullptr);
    EXPECT_EQ(MacAddress(eth_header->dstMac), dst);
    EXPECT_EQ(MacAddress(eth_header->srcMac), src);
    EXPECT_EQ(casket::be_to_host(eth_header->etherType), static_cast<uint16_t>(EtherType::IP));
}

TEST(PacketBuilderTest, EthernetWithVlan)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto eth = builder.eth();
    eth.set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::VLAN)))
       .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 4);
    EXPECT_EQ(builder.offset(), 18);

    auto* eth_header = reinterpret_cast<ethernet_header*>(builder.buffer());
    ASSERT_NE(eth_header, nullptr);
    EXPECT_EQ(MacAddress(eth_header->dstMac), dst);
    EXPECT_EQ(MacAddress(eth_header->srcMac), src);
    EXPECT_EQ(casket::be_to_host(eth_header->etherType), static_cast<uint16_t>(EtherType::VLAN));
}

TEST(PacketBuilderTest, IPv4WithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto srcIp = IPv4Address("192.168.1.10");
    auto dstIp = IPv4Address("10.0.0.5");
    
    // Ethernet
    builder.eth()
       .set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::IP)))
       .build();

    // IPv4 (ihl = 5)
    builder.ipv4()
       .apply(setVerIhl, 4, 5)
       .set(&ipv4_header::tos, 0)
       .set(&ipv4_header::ttl, 64)
       .set(&ipv4_header::protocol, IPProto::TCP)
       .set(&ipv4_header::saddr, srcIp)
       .set(&ipv4_header::daddr, dstIp)
       .build();
    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20);

    auto* ip = reinterpret_cast<ipv4_header*>(builder.buffer() + sizeof(ethernet_header));
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->version, 4);
    EXPECT_EQ(ip->ihl, 5);
    EXPECT_EQ(ip->saddr, srcIp);
    EXPECT_EQ(ip->daddr, dstIp);
}

TEST(PacketBuilderTest, IPv4WithOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto srcIp = IPv4Address("192.168.1.10");
    auto dstIp = IPv4Address("10.0.0.5");

    builder.eth()
       .set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::IP)))
       .build();

    builder.ipv4()
           .apply(setVerIhl, 4, 6)
           .set(&ipv4_header::tos, 0)
           .set(&ipv4_header::ttl, 64)
           .set(&ipv4_header::protocol, IPProto::TCP)
           .set(&ipv4_header::saddr, srcIp)
           .set(&ipv4_header::daddr, dstIp)
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 24);

    auto* ip = reinterpret_cast<ipv4_header*>(builder.buffer() + sizeof(ethernet_header));
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->ihl, 6);
}

TEST(PacketBuilderTest, TCPWithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto srcIp = IPv4Address("192.168.1.10");
    auto dstIp = IPv4Address("10.0.0.5");

    builder.eth()
       .set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::IP)))
       .build();

    builder.ipv4()
           .apply(setVerIhl, 4, 5)
           .set(&ipv4_header::tos, 0)
           .set(&ipv4_header::ttl, 64)
           .set(&ipv4_header::protocol, IPProto::TCP)
           .set(&ipv4_header::saddr, srcIp)
           .set(&ipv4_header::daddr, dstIp)
           .build();

    builder.tcp()
           .set(&tcp_header::source, casket::host_to_be(12345))
           .set(&tcp_header::dest, casket::host_to_be(80))
           .set(&tcp_header::seq, casket::be_to_host(0x100000))
           .apply([](tcp_header* h) {
               TCPBits(h)
                   .doff(5)      // 5 = 20 bytes (no options)
                   .syn(true);   // SYN flag
           })
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20 + 20);
    EXPECT_EQ(builder.offset(), 14 + 20 + 20);
}

TEST(PacketBuilderTest, TCPWithOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto srcIp = IPv4Address("192.168.1.10");
    auto dstIp = IPv4Address("10.0.0.5");

    builder.eth()
       .set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::IP)))
       .build();

     builder.ipv4()
           .apply(setVerIhl, 4, 5)
           .set(&ipv4_header::tos, 0)
           .set(&ipv4_header::ttl, 64)
           .set(&ipv4_header::protocol, IPProto::TCP)
           .set(&ipv4_header::saddr, srcIp)
           .set(&ipv4_header::daddr, dstIp)
           .build();

    builder.tcp()
           .set(&tcp_header::source, casket::host_to_be(12345))
           .set(&tcp_header::dest, casket::host_to_be(80))
           .set(&tcp_header::seq, casket::be_to_host(0x100000))
           .apply([](tcp_header* h) {
               TCPBits(h)
                   .doff(10)
                   .syn(true);
            })
           .build();

    EXPECT_EQ(builder.offset(), sizeof(ethernet_header) + 20 + 40);
    
    auto* tcp = reinterpret_cast<tcp_header*>(
        builder.buffer() + sizeof(ethernet_header) + 20
    );
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->u.bits.doff, 10);
}

TEST(PacketBuilderTest, FullPacketWithoutOptions)
{
    InMemoryPacket pkt(2048);
    PacketBuilder<InMemoryPacket> builder(&pkt);

    auto dst = MacAddress::parse("00:11:22:33:44:55");
    auto src = MacAddress::parse("AA:BB:CC:DD:EE:FF");

    auto srcIp = IPv4Address("192.168.1.10");
    auto dstIp = IPv4Address("10.0.0.5");

    builder.eth()
       .set(&ethernet_header::dstMac, dst.bytes)
       .set(&ethernet_header::srcMac, src.bytes)
       .set(&ethernet_header::etherType, casket::host_to_be(snet::to_underlying(EtherType::IP)))
       .build();

     builder.ipv4()
           .apply(setVerIhl, 4, 5)
           .set(&ipv4_header::tos, 0)
           .set(&ipv4_header::ttl, 64)
           .set(&ipv4_header::protocol, IPProto::TCP)
           .set(&ipv4_header::saddr, srcIp.toNetwork())
           .set(&ipv4_header::daddr, dstIp.toNetwork())
           .build();

    builder.tcp()
           .set(&tcp_header::source, casket::host_to_be(12345))
           .set(&tcp_header::dest, casket::host_to_be(80))
           .set(&tcp_header::seq, casket::be_to_host(0x100000))
           .apply([](tcp_header* h) {
               TCPBits(h)
                   .doff(5)
                   .syn(true);
            })
           .build();

    const char* payload = "Hello, World!";
    builder.payload(payload, std::strlen(payload));

    auto* result = builder.build();
    ASSERT_NE(result, nullptr);

    size_t expected = 14 + 20 + 20 + std::strlen(payload);
    EXPECT_EQ(builder.offset(), expected);

    auto* viewer = pkt.asPacket();
    auto ip = viewer->getHeader<IPv4Header>(IPv4);
    EXPECT_EQ(ip.srcAddr(), srcIp) << ip.srcAddr().toString() << " " << srcIp.toString();
    EXPECT_EQ(ip.dstAddr(), dstIp) << ip.dstAddr().toString() << " " << dstIp.toString();

    auto tcp = viewer->getHeader<TCPHeader>(TCP);
    EXPECT_TRUE(tcp.isSYN());
}
