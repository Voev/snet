#include <gtest/gtest.h>
#include <snet/layers/l3/ipv4_address.hpp>

using namespace snet::layers;

std::string testIP("192.168.0.225");

TEST(IPv4AddressTest, Constructor)
{
    IPv4Address addr1(testIP);
    IPv4Address addr2(testIP);
    EXPECT_EQ(addr2, addr1);
    EXPECT_EQ(addr1.toString(), testIP);
    EXPECT_EQ(addr2.toString(), testIP);
    EXPECT_NE(addr1, IPv4Address("192.168.0.254"));
}

TEST(IPv4AddressTest, CopyAssignmentOperator)
{
    IPv4Address addr1(testIP);
    uint32_t as_int = addr1;
    IPv4Address addr2;
    addr2 = IPv4Address(as_int);
    EXPECT_EQ(addr1, addr2);
    uint32_t as_int2 = addr2;
    EXPECT_EQ(as_int2, as_int);
}

TEST(IPv4AddressTest, OutputOperator)
{
    IPv4Address addr(testIP);
    std::ostringstream oss;
    oss << addr;
    EXPECT_EQ(oss.str(), testIP);
}

TEST(IPv4AddressTest, EqualityOperator)
{
    IPv4Address addr1(testIP), addr2(testIP);
    EXPECT_EQ(addr1, addr2);
    EXPECT_NE(addr1, IPv4Address("127.0.0.1"));
}

TEST(IPv4AddressTest, LessThanOperator)
{
    IPv4Address addr1(testIP), addr2(testIP);
    EXPECT_FALSE(addr1 < addr2);
    EXPECT_LT(addr1, IPv4Address("192.168.1.2"));
    EXPECT_LT(addr1, IPv4Address("192.168.0.226"));
    EXPECT_LT(addr1, IPv4Address("193.0.0.0"));
    EXPECT_LE(addr1, addr2);
}

TEST(IPv4AddressTest, GreaterThanOperator)
{
    IPv4Address addr1(testIP), addr2(testIP);
    EXPECT_FALSE(addr1 < addr2);
    EXPECT_GT(addr1, IPv4Address("192.167.1.2"));
    EXPECT_GT(addr1, IPv4Address("192.167.0.226"));
    EXPECT_GT(addr1, IPv4Address("191.0.0.0"));
    EXPECT_GE(addr1, addr2);
}

TEST(IPv4AddressTest, IsLoopback)
{
    EXPECT_TRUE(IPv4Address("127.0.0.1").isLoopback());
    EXPECT_TRUE(IPv4Address("127.0.0.0").isLoopback());
    EXPECT_TRUE(IPv4Address("127.255.255.254").isLoopback());
    EXPECT_FALSE(IPv4Address("126.255.255.254").isLoopback());
    EXPECT_FALSE(IPv4Address("128.0.0.0").isLoopback());
}

TEST(IPv4AddressTest, IsMulticast)
{
    EXPECT_TRUE(IPv4Address("224.0.0.1").isMulticast());
    EXPECT_TRUE(IPv4Address("226.3.54.132").isMulticast());
    EXPECT_TRUE(IPv4Address("239.255.255.255").isMulticast());
    EXPECT_FALSE(IPv4Address("223.255.255.255").isMulticast());
    EXPECT_FALSE(IPv4Address("240.0.0.0").isMulticast());
}

TEST(IPv4AddressTest, IsBroadcast)
{
    EXPECT_TRUE(IPv4Address("255.255.255.255").isBroadcast());
    EXPECT_FALSE(IPv4Address("226.3.54.132").isBroadcast());
    EXPECT_FALSE(IPv4Address("127.0.0.1").isBroadcast());
}

TEST(IPv4AddressTest, IsUnicast)
{
    EXPECT_FALSE(IPv4Address("255.255.255.255").isUnicast());
    EXPECT_FALSE(IPv4Address("224.0.0.1").isUnicast());
    EXPECT_TRUE(IPv4Address("240.0.0.0").isUnicast());
    EXPECT_TRUE(IPv4Address("127.0.0.1").isUnicast());
}

TEST(IPv4AddressTest, Mask)
{
    EXPECT_EQ(IPv4Address("192.168.100.0"), IPv4Address("192.168.100.1") & IPv4Address("255.255.255.0"));
    EXPECT_EQ(IPv4Address("192.128.0.0"), IPv4Address("192.255.1.2") & IPv4Address("255.128.0.0"));
}

TEST(IPv4AddressTest, OrMask)
{
    EXPECT_EQ(IPv4Address("255.255.255.1"), IPv4Address("192.168.100.1") | IPv4Address("255.255.255.0"));
    EXPECT_EQ(IPv4Address("255.255.1.2"), IPv4Address("192.255.1.2") | IPv4Address("255.128.0.0"));
}

TEST(IPv4AddressTest, NotMask)
{
    EXPECT_EQ(IPv4Address("0.0.0.255"), ~IPv4Address("255.255.255.0"));
    EXPECT_EQ(IPv4Address("0.127.255.255"), ~IPv4Address("255.128.0.0"));
}
