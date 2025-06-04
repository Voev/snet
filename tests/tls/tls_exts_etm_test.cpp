#include <gtest/gtest.h>
#include <snet/tls/exts/encrypt_then_mac.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace snet::utils;
using namespace casket::utils;

class EncryptThenMACTest : public ::testing::Test
{
};

TEST_F(EncryptThenMACTest, EmptySpanConstruction)
{
    ASSERT_NO_THROW(EncryptThenMAC etm(std::span<const uint8_t>{}));
}

TEST_F(EncryptThenMACTest, NonEmptySpanConstruction)
{
    uint8_t dummy = 0;
    std::span<const uint8_t> span(&dummy, 1);
    ASSERT_THROW(EncryptThenMAC etm(span), RuntimeError);
}

TEST_F(EncryptThenMACTest, Serialization)
{
    std::vector<uint8_t> buffer(10);
    std::vector<uint8_t> buffer2(10);
    size_t written;

    EncryptThenMAC etm;
    ASSERT_NO_THROW(written = etm.serialize(Side::Client, buffer));
    ASSERT_EQ(written, 0);
    buffer.resize(written);

    EncryptThenMAC etm2(buffer);
    ASSERT_NO_THROW(written = etm2.serialize(Side::Server, buffer2));
    ASSERT_EQ(written, 0);
    buffer2.resize(written);

    ASSERT_EQ(buffer, buffer2);
}
