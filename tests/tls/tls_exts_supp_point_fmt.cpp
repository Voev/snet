#include <gtest/gtest.h>
#include <snet/tls/exts/supported_point_formats.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace casket::utils;

class SupportedPointFormatsTest : public ::testing::Test
{
};

TEST_F(SupportedPointFormatsTest, SerializeProducesCorrectOutput)
{
    std::vector<ECPointFormat> uncompressedOnly = {ECPointFormat::UNCOMPRESSED};
    SupportedPointFormats formats(uncompressedOnly);

    uint8_t buffer[32];
    auto written = formats.serialize(Side::Client, buffer);

    EXPECT_EQ(2, written);
    EXPECT_EQ(1, buffer[0]);
    EXPECT_EQ(0, buffer[1]);
}

TEST_F(SupportedPointFormatsTest, DeserializeHandlesValidInput)
{
    const uint8_t serialized[] = {3, 0, 1, 2};
    SupportedPointFormats formats(Side::Server, serialized);

    EXPECT_EQ(3, formats.getFormats().size());
    EXPECT_EQ(ECPointFormat::UNCOMPRESSED, formats.getFormats()[0]);
    EXPECT_EQ(ECPointFormat::ANSIX962_COMPRESSED_PRIME, formats.getFormats()[1]);
    EXPECT_EQ(ECPointFormat::ANSIX962_COMPRESSED_CHAR2, formats.getFormats()[2]);
}

TEST_F(SupportedPointFormatsTest, DeserializeThrowsOnInvalidFormat)
{
    const uint8_t serialized[] = {1, 3};
    EXPECT_THROW(SupportedPointFormats formats(Side::Client, serialized), RuntimeError);
}

TEST_F(SupportedPointFormatsTest, DeserializeThrowsOnLengthMismatch)
{
    const uint8_t serialized[] = {2, 0};
    EXPECT_THROW(SupportedPointFormats formats(Side::Client, serialized), RuntimeError);
}

TEST_F(SupportedPointFormatsTest, RoundTripSerialization)
{
    std::vector<ECPointFormat> mixedFormats = {ECPointFormat::UNCOMPRESSED, ECPointFormat::ANSIX962_COMPRESSED_CHAR2,
                                               ECPointFormat::ANSIX962_COMPRESSED_PRIME};

    SupportedPointFormats original(mixedFormats);
    uint8_t buffer[32];
    auto written = original.serialize(Side::Client, buffer);

    SupportedPointFormats deserialized(Side::Server, {buffer, written});
    EXPECT_EQ(original.getFormats(), deserialized.getFormats());
}