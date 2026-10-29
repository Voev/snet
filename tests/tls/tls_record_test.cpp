#include <gtest/gtest.h>
#include <snet/tls/record.hpp>

using namespace snet::tls;

namespace {

constexpr uint8_t kHandshakeHeaderTLS12[] = {22, 3, 3, 0, 10};
constexpr uint8_t kCCSHeaderTLS12[]       = {20, 3, 3, 0, 1};

} // namespace

TEST(RecordTest, DefaultConstructorState)
{
    Record rec;
    EXPECT_EQ(rec.getType(), RecordType::Invalid);
    EXPECT_EQ(rec.getLength(), 0u);
    EXPECT_TRUE(rec.getCiphertext().empty());
    EXPECT_TRUE(rec.getPlaintext().empty());
    EXPECT_FALSE(rec.isPlaintext());
    EXPECT_FALSE(rec.mustBeEncrypted());
    EXPECT_TRUE(rec.isFullyAssembled());
}

TEST(RecordTest, TypeConstructorState)
{
    Record rec(RecordType::Handshake);
    EXPECT_EQ(rec.getType(), RecordType::Handshake);
    EXPECT_EQ(rec.getLength(), 0u);
}

TEST(RecordTest, DeserializeHeaderRejectsTooShortInput)
{
    Record rec;
    const uint8_t tooShort[3] = {22, 3, 3};
    EXPECT_THROW(rec.deserializeHeader(tooShort), std::exception);
}

TEST(RecordTest, DeserializeHeaderRejectsInvalidType)
{
    Record rec;
    const uint8_t bad[5] = {99, 3, 3, 0, 10};
    EXPECT_THROW(rec.deserializeHeader(bad), std::exception);
}

TEST(RecordTest, DeserializeHeaderRejectsInvalidVersion)
{
    Record rec;
    const uint8_t bad[5] = {22, 4, 0, 0, 10};   // major != 3
    EXPECT_THROW(rec.deserializeHeader(bad), std::exception);

    const uint8_t bad2[5] = {22, 3, 4, 0, 10};  // minor >= 4
    EXPECT_THROW(rec.deserializeHeader(bad2), std::exception);
}

TEST(RecordTest, DeserializeHeaderRejectsEmptyRecord)
{
    Record rec;
    const uint8_t empty[5] = {22, 3, 3, 0, 0};
    EXPECT_THROW(rec.deserializeHeader(empty), std::exception);
}

TEST(RecordTest, DeserializeHeaderRejectsTooLargeRecord)
{
    Record rec;
    const uint8_t tooBig[5] = {22, 3, 3, 0xFF, 0xFF};
    EXPECT_THROW(rec.deserializeHeader(tooBig), std::exception);
}

TEST(RecordTest, DeserializeHeaderParsesFields)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    EXPECT_EQ(rec.getType(), RecordType::Handshake);
    EXPECT_EQ(rec.getVersion().majorVersion(), 3);
    EXPECT_EQ(rec.getVersion().minorVersion(), 3);
    EXPECT_FALSE(rec.isFullyAssembled());
}

TEST(RecordTest, SerializeDeserializeHeaderRoundTrip)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    uint8_t out[5] = {0};
    EXPECT_EQ(rec.serializeHeader(out), 5u);
    EXPECT_EQ(std::memcmp(out, kHandshakeHeaderTLS12, 5), 0);
}

TEST(RecordTest, SerializeHeaderRejectsSmallOutput)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    uint8_t tiny[4];
    EXPECT_THROW(rec.serializeHeader(tiny), std::exception);
}

TEST(RecordTest, InitCiphertextZeroCopy)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    uint8_t data[10] = {1,2,3,4,5,6,7,8,9,10};
    EXPECT_EQ(rec.initCiphertext(data), 10u);
    EXPECT_TRUE(rec.isFullyAssembled());

    auto ct = rec.getCiphertext();
    ASSERT_EQ(ct.size(), 10u);
    EXPECT_EQ(ct.data(), data);
    EXPECT_EQ(std::memcmp(ct.data(), data, 10), 0);
}

TEST(RecordTest, InitCiphertextCopiesWhenIncomplete)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    const uint8_t part1[4] = {1,2,3,4};
    const uint8_t part2[6] = {5,6,7,8,9,10};

    EXPECT_EQ(rec.initCiphertext(part1), 4u);
    EXPECT_FALSE(rec.isFullyAssembled());
    EXPECT_EQ(rec.getCiphertext().size(), 4u);

    EXPECT_EQ(rec.initCiphertext(part2), 6u);
    EXPECT_TRUE(rec.isFullyAssembled());

    auto ct = rec.getCiphertext();
    ASSERT_EQ(ct.size(), 10u);
    EXPECT_EQ(ct[0], 1);
    EXPECT_EQ(ct[9], 10);
}

TEST(RecordTest, InitCiphertextRepeatedCallAfterCompleteIsNoop)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);

    uint8_t data[10] = {1,2,3,4,5,6,7,8,9,10};
    ASSERT_EQ(rec.initCiphertext(data), 10u);
    auto originalData = rec.getCiphertext().data();

    EXPECT_EQ(rec.initCiphertext(data), 0u);
    EXPECT_EQ(rec.getCiphertext().data(), originalData);
    EXPECT_TRUE(rec.isFullyAssembled());
}

TEST(RecordTest, ResetClearsAllState)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);
    uint8_t data[10] = {1,2,3,4,5,6,7,8,9,10};
    rec.initCiphertext(data);

    rec.reset();

    EXPECT_EQ(rec.getType(), RecordType::Invalid);
    EXPECT_EQ(rec.getLength(), 0u);
    EXPECT_TRUE(rec.getCiphertext().empty());
    EXPECT_TRUE(rec.getPlaintext().empty());
    EXPECT_FALSE(rec.isPlaintext());
    EXPECT_FALSE(rec.mustBeEncrypted());
    EXPECT_TRUE(rec.isFullyAssembled());
}

TEST(RecordTest, DeserializeHeaderAfterResetStartsFreshAssembly)
{
    Record rec;
    rec.deserializeHeader(kHandshakeHeaderTLS12);
    uint8_t data[10] = {0};
    ASSERT_EQ(rec.initCiphertext(data), 10u);

    rec.deserializeHeader(kHandshakeHeaderTLS12);   
    EXPECT_FALSE(rec.isFullyAssembled());
    EXPECT_EQ(rec.initCiphertext(data), 10u);
}

TEST(RecordTest, SerializeChangeCipherSpec)
{
    Record rec;
    ProtocolVersion version(3, 3);

    EXPECT_EQ(rec.serializeChangeCipherSpec(version), 1u);
    EXPECT_EQ(rec.getType(), RecordType::ChangeCipherSpec);
    EXPECT_EQ(rec.getVersion().majorVersion(), 3);
    EXPECT_EQ(rec.getVersion().minorVersion(), 3);
    EXPECT_TRUE(rec.isPlaintext());
    EXPECT_FALSE(rec.mustBeEncrypted());

    auto pt = rec.getPlaintext();
    ASSERT_EQ(pt.size(), 1u);
    EXPECT_EQ(pt[0], 0x01);

    EXPECT_TRUE(rec.isFullyAssembled());
}

TEST(RecordTest, InitPlaintextBasic)
{
    Record rec;
    const uint8_t data[3] = {0xAA, 0xBB, 0xCC};

    EXPECT_EQ(rec.initPlaintext(data), 3u);
    EXPECT_EQ(rec.getPlaintext().size(), 3u);
    EXPECT_EQ(rec.getPlaintext()[0], 0xAA);
    EXPECT_TRUE(rec.isFullyAssembled());
}

TEST(RecordTest, GetPlaintextOffsetAfterInitPlaintext)
{
    Record rec;
    const uint8_t data[4] = {1,2,3,4};
    rec.initPlaintext(data);

    auto off = rec.getPlaintextOffset();
    EXPECT_EQ(off.size(), 4u);
    EXPECT_EQ(off.data(), rec.getPlaintext().data());
}