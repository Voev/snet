#include <gtest/gtest.h>
#include <snet/tls/version.hpp>

using namespace snet::tls;

TEST(ProtocolVersionTest, DefaultConstructor) {
    ProtocolVersion version;
    ASSERT_EQ(version.majorVersion(), 0);
    ASSERT_EQ(version.minorVersion(), 0);
    ASSERT_EQ(version.code(), 0);
}

TEST(ProtocolVersionTest, ConstructorFromCode) {
    ProtocolVersion version(0x0301);
    ASSERT_EQ(version.majorVersion(), 3);
    ASSERT_EQ(version.minorVersion(), 1);
    ASSERT_EQ(version.code(), 0x0301);
}

TEST(ProtocolVersionTest, ConstructorFromMajorMinor) {
    ProtocolVersion version(3, 3);
    ASSERT_EQ(version.majorVersion(), 3);
    ASSERT_EQ(version.minorVersion(), 3);
    ASSERT_EQ(version.code(), 0x0303);
}

TEST(ProtocolVersionTest, ToString) {
    ProtocolVersion version(3, 3);
    ASSERT_EQ(version.toString(), "TLSv1.2");
}

TEST(ProtocolVersionTest, FromString) {
    auto versionOpt = ProtocolVersion::fromString("TLSv1.2");
    ASSERT_TRUE(versionOpt.has_value());
    ProtocolVersion version = *versionOpt;
    ASSERT_EQ(version.majorVersion(), 3);
    ASSERT_EQ(version.minorVersion(), 3);
}

TEST(ProtocolVersionTest, EqualityOperator) {
    ProtocolVersion version1(3, 3);
    ProtocolVersion version2(3, 3);
    ASSERT_TRUE(version1 == version2);
}

TEST(ProtocolVersionTest, InequalityOperator) {
    ProtocolVersion version1(3, 3);
    ProtocolVersion version2(3, 2);
    ASSERT_TRUE(version1 != version2);
}

TEST(ProtocolVersionTest, ComparisonOperators) {
    ProtocolVersion version1(3, 3);
    ProtocolVersion version2(3, 4);
    ASSERT_TRUE(version2 > version1);
    ASSERT_TRUE(version2 >= version1);
    ASSERT_TRUE(version1 < version2);
    ASSERT_TRUE(version1 <= version2);
}

TEST(ProtocolVersionRangeTest, ParseProtocolVersionRange) {
    auto rangeOpt = ParseProtocolVersionRange("TLSv1.0-TLSv1.2");
    ASSERT_TRUE(rangeOpt.has_value());

    ProtocolVersionRange range = *rangeOpt;
    ASSERT_EQ(range.first.majorVersion(), 3);
    ASSERT_EQ(range.first.minorVersion(), 1);
    ASSERT_EQ(range.second.majorVersion(), 3);
    ASSERT_EQ(range.second.minorVersion(), 3);
}
