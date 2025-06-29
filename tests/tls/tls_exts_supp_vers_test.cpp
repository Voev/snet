#include <gtest/gtest.h>
#include <snet/tls/exts/supported_versions.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket;

class SupportedVersionsTest : public ::testing::Test
{
};

TEST_F(SupportedVersionsTest, ConstructionWithSingleVersion)
{
    SupportedVersions sv(ProtocolVersion::TLSv1_3);
    ASSERT_EQ(sv.versions().size(), 1);
    ASSERT_EQ(sv.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, ClientSideConstruction)
{
    uint8_t client_data[] = {0x04, 0x03, 0x03, 0x03, 0x04}; // 2 versions: TLS 1.2 and TLS 1.3
    SupportedVersions sv(Side::Client, client_data);

    ASSERT_EQ(sv.versions().size(), 2);
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_2));
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_3));
}

TEST_F(SupportedVersionsTest, ServerSideConstruction)
{
    uint8_t server_data[] = {0x03, 0x04}; // TLS 1.3
    SupportedVersions sv(Side::Server, server_data);

    ASSERT_EQ(sv.versions().size(), 1);
    ASSERT_EQ(sv.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, InvalidServerConstruction)
{
    uint8_t invalidData[] = {0x03, 0x04, 0x05}; // Too much data
    ASSERT_THROW(SupportedVersions(Side::Server, invalidData), RuntimeError);
}

TEST_F(SupportedVersionsTest, ClientSerialization)
{
    std::vector<ProtocolVersion> versions = {ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3};
    SupportedVersions sv(versions);

    std::vector<uint8_t> buffer(10);
    size_t written = sv.serialize(Side::Client, buffer);
    buffer.resize(written);

    SupportedVersions sv2(Side::Client, buffer);
    ASSERT_EQ(sv2.versions(), versions);
}

TEST_F(SupportedVersionsTest, ServerSerialization)
{
    SupportedVersions sv(ProtocolVersion::TLSv1_3);

    std::vector<uint8_t> buffer(10);
    size_t written = sv.serialize(Side::Client, buffer);
    buffer.resize(written);

    SupportedVersions sv2(Side::Client, buffer);
    ASSERT_EQ(sv2.versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(SupportedVersionsTest, SupportsMethod)
{
    std::vector<ProtocolVersion> versions = {ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3};
    SupportedVersions sv(std::move(versions));

    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_2));
    ASSERT_TRUE(sv.supports(ProtocolVersion::TLSv1_3));
    ASSERT_FALSE(sv.supports(ProtocolVersion::TLSv1_1));
}
