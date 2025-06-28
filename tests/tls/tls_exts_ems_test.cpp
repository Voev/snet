#include <gtest/gtest.h>
#include <snet/tls/exts/extended_master_secret.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket::utils;

class ExtendedMasterSecretTest : public ::testing::Test
{
};

TEST_F(ExtendedMasterSecretTest, EmptySpanConstruction)
{
    ASSERT_NO_THROW(ExtendedMasterSecret(cpp::span<const uint8_t>{}));
}

TEST_F(ExtendedMasterSecretTest, NonEmptySpanConstruction)
{
    uint8_t dummy = 0;
    cpp::span<const uint8_t> span(&dummy, 1);
    ASSERT_THROW(ExtendedMasterSecret ems(span), RuntimeError);
}

TEST_F(ExtendedMasterSecretTest, Serialization)
{
    std::vector<uint8_t> buffer(10);
    std::vector<uint8_t> buffer2(10);
    size_t written;

    ExtendedMasterSecret ems;
    ASSERT_NO_THROW(written = ems.serialize(Side::Client, buffer));
    ASSERT_EQ(written, 0);
    buffer.resize(written);

    ExtendedMasterSecret ems2(buffer);
    ASSERT_NO_THROW(written = ems2.serialize(Side::Server, buffer2));
    ASSERT_EQ(written, 0);
    buffer2.resize(written);

    ASSERT_EQ(buffer, buffer2);
}
