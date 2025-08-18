#include <gtest/gtest.h>
#include <snet/tls/extensions.hpp>
#include <snet/tls/exts/supported_versions.hpp>
#include <snet/tls/exts/server_name_indication.hpp>
#include <snet/tls/exts/record_size_limit.hpp>

using namespace snet::tls;

class ExtensionsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        supportedVersions = std::make_unique<SupportedVersions>(ProtocolVersion::TLSv1_3);
        serverName = std::make_unique<ServerNameIndicator>("example.com");
        recordSizeLimit = std::make_unique<RecordSizeLimit>(1500);
    }

    std::unique_ptr<Extension> supportedVersions;
    std::unique_ptr<Extension> serverName;
    std::unique_ptr<Extension> recordSizeLimit;
};

TEST_F(ExtensionsTest, DefaultConstructorCreatesEmptyExtensions)
{
    Extensions exts;
    EXPECT_TRUE(exts.empty());
    EXPECT_EQ(0, exts.size());
}

TEST_F(ExtensionsTest, AddIncreasesSize)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    EXPECT_EQ(1, exts.size());
    exts.add(std::move(serverName));
    EXPECT_EQ(2, exts.size());
}

TEST_F(ExtensionsTest, GetReturnsCorrectExtension)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    exts.add(std::move(serverName));

    auto* sv = exts.get<SupportedVersions>();
    ASSERT_NE(nullptr, sv);
    EXPECT_EQ(ProtocolVersion(ProtocolVersion::TLSv1_3), sv->versions()[0]);

    auto* sni = exts.get<ServerNameIndicator>();
    ASSERT_NE(nullptr, sni);
    EXPECT_EQ("example.com", sni->getHostname());
}

TEST_F(ExtensionsTest, HasReturnsCorrectResults)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));

    EXPECT_TRUE(exts.has<SupportedVersions>());
    EXPECT_TRUE(exts.has(ExtensionCode::SupportedVersions));
    EXPECT_FALSE(exts.has<ServerNameIndicator>());
    EXPECT_FALSE(exts.has(ExtensionCode::ServerNameIndication));
}

TEST_F(ExtensionsTest, TakeRemovesAndReturnsExtension)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    exts.add(std::move(serverName));

    auto taken = exts.take<SupportedVersions>();
    ASSERT_NE(nullptr, taken);
    EXPECT_EQ(1, exts.size());
    EXPECT_FALSE(exts.has<SupportedVersions>());
}

TEST_F(ExtensionsTest, RemoveExtensionWorks)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));

    EXPECT_TRUE(exts.removeExtension(ExtensionCode::SupportedVersions));
    EXPECT_FALSE(exts.has<SupportedVersions>());
    EXPECT_FALSE(exts.removeExtension(ExtensionCode::ServerNameIndication));
}

TEST_F(ExtensionsTest, ExtensionTypesReturnsCorrectSet)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    exts.add(std::move(serverName));

    auto types = exts.extensionTypes();
    EXPECT_EQ(2, types.size());
    EXPECT_TRUE(types.count(ExtensionCode::SupportedVersions));
    EXPECT_TRUE(types.count(ExtensionCode::ServerNameIndication));
}

TEST_F(ExtensionsTest, ContainsOtherThanWorks)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    exts.add(std::move(serverName));

    std::set<ExtensionCode> allowed = {ExtensionCode::SupportedVersions};
    EXPECT_TRUE(exts.containsOtherThan(allowed));
    EXPECT_FALSE(exts.containsOtherThan({ExtensionCode::SupportedVersions, ExtensionCode::ServerNameIndication}));
}

TEST_F(ExtensionsTest, DeserializeCreatesCorrectExtensions)
{
    // Create a synthetic extensions block with SupportedVersions
    std::vector<uint8_t> data = {
        0x00, 0x07,
        0x00, 0x2b, // SupportedVersions type
        0x00, 0x03, // Length = 3 bytes
        0x02,       // Length of versions list = 2 bytes
        0x03, 0x04  // TLS 1.3
    };

    Extensions exts(Side::Client, data, HandshakeType::ClientHelloCode);
    EXPECT_EQ(1, exts.size());
    EXPECT_TRUE(exts.has<SupportedVersions>());

    auto* sv = exts.get<SupportedVersions>();
    ASSERT_NE(nullptr, sv);
    EXPECT_EQ(ProtocolVersion(ProtocolVersion::TLSv1_3), sv->versions()[0]);
}

TEST_F(ExtensionsTest, MoveOperationsWork)
{
    Extensions exts1;
    exts1.add(std::move(supportedVersions));
    exts1.add(std::move(serverName));

    // Test move constructor
    Extensions exts2(std::move(exts1));
    EXPECT_EQ(2, exts2.size());
    EXPECT_TRUE(exts1.empty());

    // Test move assignment
    Extensions exts3;
    exts3 = std::move(exts2);
    EXPECT_EQ(2, exts3.size());
    EXPECT_TRUE(exts2.empty());
}

TEST_F(ExtensionsTest, AllReturnsAllExtensions)
{
    Extensions exts;
    exts.add(std::move(supportedVersions));
    exts.add(std::move(serverName));

    const auto& all = exts.all();
    EXPECT_EQ(2, all.size());
    EXPECT_NE(nullptr, dynamic_cast<SupportedVersions*>(all[0].get()));
    EXPECT_NE(nullptr, dynamic_cast<ServerNameIndicator*>(all[1].get()));
}