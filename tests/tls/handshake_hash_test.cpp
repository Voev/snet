#include <gtest/gtest.h>
#include <snet/tls/handshake_hash.hpp>
#include <snet/crypto/exception.hpp>

using namespace snet::tls;

class HandshakeHashTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }

    HandshakeHash hash;
};

TEST_F(HandshakeHashTest, DefaultConstructor) {
    ASSERT_TRUE(hash.getContents().empty());
}

TEST_F(HandshakeHashTest, UpdateMethod) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    hash.update(data);
    ASSERT_EQ(hash.getContents(), data);
}

TEST_F(HandshakeHashTest, FinalMethod) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    hash.update(data);
    auto result = hash.final("SHA-256");
    ASSERT_FALSE(result.empty());
    ASSERT_EQ(result.size(), 32);
}

TEST_F(HandshakeHashTest, GetContentsMethod) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    hash.update(data);
    ASSERT_EQ(hash.getContents(), data);
}
TEST_F(HandshakeHashTest, ResetMethod) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    hash.update(data);
    hash.reset();
    ASSERT_TRUE(hash.getContents().empty());
}

TEST_F(HandshakeHashTest, MultipleUpdates) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data2 = {0x04, 0x05, 0x06};
    hash.update(data1);
    hash.update(data2);
    std::vector<uint8_t> expected = data1;
    expected.insert(expected.end(), data2.begin(), data2.end());
    ASSERT_EQ(hash.getContents(), expected);
}

TEST_F(HandshakeHashTest, FinalMethodEmptyInput) {
    auto result = hash.final("SHA-256");
    ASSERT_FALSE(result.empty());
    ASSERT_EQ(result.size(), 32);
}

TEST_F(HandshakeHashTest, FinalMethodUnsupportedAlgorithm) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    hash.update(data);
    ASSERT_THROW(hash.final("UNSUPPORTED_ALGORITHM"), snet::crypto::Exception);
}
