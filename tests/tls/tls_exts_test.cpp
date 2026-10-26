#include <gtest/gtest.h>
#include <snet/tls/extensions.hpp>

using namespace snet;
using namespace snet::tls;

class ExtensionsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        exts_.add(ExtensionVariant(SupportedVersions(ProtocolVersion::TLSv1_3)));
        exts_.add(ExtensionVariant(ServerNameIndicator("example.com")));
        exts_.add(ExtensionVariant(RecordSizeLimit(1500)));
    }

    Extensions exts_;
};

TEST_F(ExtensionsTest, DefaultConstructorCreatesEmptyExtensions)
{
    Extensions e;
    ASSERT_TRUE(e.empty());
    ASSERT_EQ(e.size(), 0u);
}

TEST_F(ExtensionsTest, AddIncreasesSize)
{
    Extensions e;
    ASSERT_TRUE(e.add(ExtensionVariant(SupportedVersions(ProtocolVersion::TLSv1_3))));
    ASSERT_EQ(e.size(), 1u);

    ASSERT_TRUE(e.add(ExtensionVariant(ServerNameIndicator("example.com"))));
    ASSERT_EQ(e.size(), 2u);
}

TEST_F(ExtensionsTest, AddRejectsDuplicate)
{
    Extensions e;
    ASSERT_TRUE(e.add(ExtensionVariant(SupportedVersions(ProtocolVersion::TLSv1_3))));
    ASSERT_FALSE(e.add(ExtensionVariant(SupportedVersions(ProtocolVersion::TLSv1_2))));
    ASSERT_EQ(e.size(), 1u);
}

TEST_F(ExtensionsTest, GetReturnsCorrectExtension)
{
    auto* sv = exts_.get<SupportedVersions>();
    ASSERT_NE(sv, nullptr);
    ASSERT_EQ(sv->versions().size(), 1u);
    ASSERT_EQ(sv->versions()[0], ProtocolVersion::TLSv1_3);

    auto* sni = exts_.get<ServerNameIndicator>();
    ASSERT_NE(sni, nullptr);
    ASSERT_EQ(sni->getHostname(), "example.com");

    auto* rsl = exts_.get<RecordSizeLimit>();
    ASSERT_NE(rsl, nullptr);
    ASSERT_EQ(rsl->limit(), 1500);
}

TEST_F(ExtensionsTest, GetReturnsNullptrForMissing)
{
    ASSERT_EQ(exts_.get<ALPN>(), nullptr);
    ASSERT_EQ(exts_.get(ExtensionCode::AppLayerProtocolNegotiation), nullptr);
}

TEST_F(ExtensionsTest, HasReturnsCorrectResults)
{
    ASSERT_TRUE(exts_.has<SupportedVersions>());
    ASSERT_TRUE(exts_.has(ExtensionCode::SupportedVersions));
    ASSERT_TRUE(exts_.has<ServerNameIndicator>());
    ASSERT_TRUE(exts_.has(ExtensionCode::ServerNameIndication));

    ASSERT_FALSE(exts_.has<ALPN>());
    ASSERT_FALSE(exts_.has(ExtensionCode::AppLayerProtocolNegotiation));
}

TEST_F(ExtensionsTest, TakeRemovesAndReturnsExtension)
{
    auto taken = exts_.take<SupportedVersions>();
    ASSERT_TRUE(taken.has_value());
    ASSERT_EQ(taken->versions().size(), 1u);
    ASSERT_EQ(exts_.size(), 2u);
    ASSERT_FALSE(exts_.has<SupportedVersions>());
}

TEST_F(ExtensionsTest, TakeReturnsNulloptForMissing)
{
    ASSERT_FALSE(exts_.take<ALPN>().has_value());
    ASSERT_FALSE(exts_.take(ExtensionCode::AppLayerProtocolNegotiation).has_value());
    ASSERT_EQ(exts_.size(), 3u);
}

TEST_F(ExtensionsTest, RemoveExtensionWorks)
{
    ASSERT_TRUE(exts_.removeExtension(ExtensionCode::SupportedVersions));
    ASSERT_FALSE(exts_.has<SupportedVersions>());
    ASSERT_FALSE(exts_.removeExtension(ExtensionCode::AppLayerProtocolNegotiation));
}

TEST_F(ExtensionsTest, ExtensionTypesReturnsCorrectSet)
{
    const auto types = exts_.extensionTypes();
    ASSERT_EQ(types.size(), 3u);
    ASSERT_TRUE(types.count(ExtensionCode::SupportedVersions));
    ASSERT_TRUE(types.count(ExtensionCode::ServerNameIndication));
    ASSERT_TRUE(types.count(ExtensionCode::RecordSizeLimit));
}

TEST_F(ExtensionsTest, ContainsOtherThanWorks)
{
    ASSERT_TRUE(exts_.containsOtherThan({ExtensionCode::SupportedVersions}));
    ASSERT_FALSE(exts_.containsOtherThan({
        ExtensionCode::SupportedVersions,
        ExtensionCode::ServerNameIndication,
        ExtensionCode::RecordSizeLimit,
    }));
}

TEST_F(ExtensionsTest, ContainsImplementedExtensionsOtherThan)
{
    ASSERT_TRUE(exts_.containsImplementedExtensionsOtherThan({
        ExtensionCode::SupportedVersions,
    }));
    ASSERT_FALSE(exts_.containsImplementedExtensionsOtherThan({
        ExtensionCode::SupportedVersions,
        ExtensionCode::ServerNameIndication,
        ExtensionCode::RecordSizeLimit,
    }));
}

TEST_F(ExtensionsTest, DeserializeCreatesCorrectExtensions)
{
    const std::vector<uint8_t> data = {
        0x00, 0x07,
        0x00, 0x2B,
        0x00, 0x03,
        0x02,
        0x03, 0x04,
    };

    Extensions e;
    ASSERT_EQ(e.deserialize(Side::Client, data, HandshakeType::ClientHelloCode),
              utils::DecodeError::None);
    ASSERT_EQ(e.size(), 1u);
    ASSERT_TRUE(e.has<SupportedVersions>());

    auto* sv = e.get<SupportedVersions>();
    ASSERT_NE(sv, nullptr);
    ASSERT_EQ(sv->versions().size(), 1u);
    ASSERT_EQ(sv->versions()[0], ProtocolVersion::TLSv1_3);
}

TEST_F(ExtensionsTest, DeserializeFailsOnBadTotalLength)
{
    const std::vector<uint8_t> data = {
        0x00, 0xFF,
        0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04,
    };

    Extensions e;
    ASSERT_EQ(e.deserialize(Side::Client, data, HandshakeType::ClientHelloCode),
              utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(e.empty());
}

TEST_F(ExtensionsTest, DeserializeFailsOnTruncatedInput)
{
    const std::vector<uint8_t> data = {
        0x00, 0x07,
        0x00, 0x2B, 0x00, 0x03, 0x02,
    };

    Extensions e;
    ASSERT_NE(e.deserialize(Side::Client, data, HandshakeType::ClientHelloCode),
              utils::DecodeError::None);
    ASSERT_TRUE(e.empty());
}

TEST_F(ExtensionsTest, UnknownExtensionIsPreserved)
{
    const std::vector<uint8_t> data = {
        0x00, 0x06,
        0x12, 0x34,
        0x00, 0x02,
        0xAA, 0xBB,
    };

    Extensions e;
    ASSERT_EQ(e.deserialize(Side::Client, data, HandshakeType::ClientHelloCode),
              utils::DecodeError::None);
    ASSERT_EQ(e.size(), 1u);
    ASSERT_TRUE(e.unknown().size() == 1u);

    const auto& u = e.unknown()[0];
    ASSERT_EQ(u.type(), static_cast<ExtensionCode>(0x1234));
    ASSERT_EQ(u.value().size(), 2u);
    ASSERT_EQ(u.value()[0], 0xAA);
    ASSERT_EQ(u.value()[1], 0xBB);
}

TEST_F(ExtensionsTest, MoveOperationsWork)
{
    Extensions src;
    src.add(ExtensionVariant(SupportedVersions(ProtocolVersion::TLSv1_3)));
    src.add(ExtensionVariant(ServerNameIndicator("example.com")));

    Extensions moved(std::move(src));
    ASSERT_EQ(moved.size(), 2u);
    ASSERT_TRUE(src.empty());

    Extensions assigned;
    assigned = std::move(moved);
    ASSERT_EQ(assigned.size(), 2u);
    ASSERT_TRUE(moved.empty());
}

TEST_F(ExtensionsTest, AllReturnsAllExtensions)
{
    const auto& all = exts_.all();
    ASSERT_EQ(all.size(), 3u);

    ASSERT_TRUE(std::holds_alternative<SupportedVersions>(all[0]));
    ASSERT_TRUE(std::holds_alternative<ServerNameIndicator>(all[1]));
    ASSERT_TRUE(std::holds_alternative<RecordSizeLimit>(all[2]));
}

TEST_F(ExtensionsTest, SerializeRoundtrip)
{
    std::vector<uint8_t> buffer(128, 0);
    const std::size_t written = exts_.serialize(Side::Client, buffer);
    ASSERT_NE(written, 0u);
    buffer.resize(written);

    Extensions parsed;
    ASSERT_EQ(parsed.deserialize(Side::Client, buffer, HandshakeType::ClientHelloCode),
              utils::DecodeError::None);
    ASSERT_EQ(parsed.size(), exts_.size());
    ASSERT_TRUE(parsed.has<SupportedVersions>());
    ASSERT_TRUE(parsed.has<ServerNameIndicator>());
    ASSERT_TRUE(parsed.has<RecordSizeLimit>());
}

TEST_F(ExtensionsTest, SerializeFailsOnTinyBuffer)
{
    std::vector<uint8_t> buffer(1, 0);
    ASSERT_EQ(exts_.serialize(Side::Client, buffer), 0u);
}