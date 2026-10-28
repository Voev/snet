#include <gtest/gtest.h>
#include <snet/tls/exts/alpn.hpp>

using namespace snet;
using namespace snet::tls;

class ALPNTest : public ::testing::Test
{
};

TEST_F(ALPNTest, ConstructorWithSingleProtocol)
{
    ALPN alpn("http/1.1");
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.size(), 1);
    ASSERT_EQ(alpn.singleProtocol(), "http/1.1");
}

TEST_F(ALPNTest, ConstructorWithProtocolList)
{
    std::vector<std::string> protocols = {"http/1.1", "h2", "h3"};

    ALPN alpn(protocols);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.size(), 3);

    std::vector<nonstd::string_view> parsed(alpn.protocols().begin(), alpn.protocols().end());
    ASSERT_EQ(parsed.size(), protocols.size());
    for (std::size_t i = 0; i < protocols.size(); ++i)
    {
        ASSERT_EQ(parsed[i], protocols[i]);
    }
}

TEST_F(ALPNTest, ParseFromReaderClientSide)
{
    std::vector<uint8_t> data = {0x00, 0x0C, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    ALPN alpn;
    ASSERT_EQ(alpn.deserialize(Side::Client, data), utils::DecodeError::None);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.size(), 2);

    std::vector<nonstd::string_view> parsed(alpn.protocols().begin(), alpn.protocols().end());
    ASSERT_EQ(parsed[0], "h2");
    ASSERT_EQ(parsed[1], "http/1.1");
}

TEST_F(ALPNTest, ParseFromReaderServerSide)
{
    std::vector<uint8_t> data = {0x00, 0x03, 0x02, 'h', '2'};

    ALPN alpn;
    ASSERT_EQ(alpn.deserialize(Side::Server, data), utils::DecodeError::None);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.size(), 1);
    ASSERT_EQ(alpn.singleProtocol(), "h2");
}

TEST_F(ALPNTest, ParseEmptyExtensionFails)
{
    ALPN alpn;
    ASSERT_NE(alpn.deserialize(Side::Client, {}), utils::DecodeError::None);
    ASSERT_TRUE(alpn.empty());
}

TEST_F(ALPNTest, ParseFailsOnInvalidLength)
{
    std::vector<uint8_t> data = {0x00, 0x05, 0x02, 'h', '2'};

    ALPN alpn;
    ASSERT_EQ(alpn.deserialize(Side::Client, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(alpn.empty());
}

TEST_F(ALPNTest, ParseFailsOnEmptyProtocol)
{
    std::vector<uint8_t> data = {0x00, 0x01, 0x00};

    ALPN alpn;
    ASSERT_NE(alpn.deserialize(Side::Client, data), utils::DecodeError::None);
    ASSERT_TRUE(alpn.empty());
}

TEST_F(ALPNTest, ParseFailsWhenServerSendsMultipleProtocols)
{
    std::vector<uint8_t> data = {0x00, 0x05, 0x02, 'h', '2', 0x02, 'h', '3'};

    ALPN alpn;
    ASSERT_EQ(alpn.deserialize(Side::Server, data), utils::DecodeError::LengthOutOfRange);
    ASSERT_TRUE(alpn.empty());
}

TEST_F(ALPNTest, SerializeSingleProtocol)
{
    std::vector<uint8_t> buffer(32);

    ALPN alpn("h2");
    const std::size_t written = alpn.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_GT(written, 0);
    buffer.resize(written);

    ALPN parsed;
    ASSERT_EQ(parsed.deserialize(Side::Client, buffer), utils::DecodeError::None);
    ASSERT_EQ(parsed.singleProtocol(), "h2");
}

TEST_F(ALPNTest, SerializeMultipleProtocols)
{
    std::vector<std::string> protocols = {"http/1.1", "h2", "h3"};

    ALPN alpn(protocols);
    std::vector<uint8_t> buffer(32);

    const std::size_t written = alpn.serialize(Side::Client, buffer);
    ASSERT_NE(written, kSerializationFailed);
    ASSERT_GT(written, 0);
    buffer.resize(written);

    ALPN parsed;
    ASSERT_EQ(parsed.deserialize(Side::Client, buffer), utils::DecodeError::None);
    ASSERT_EQ(parsed.size(), protocols.size());

    std::vector<nonstd::string_view> parsedProtos(parsed.protocols().begin(), parsed.protocols().end());
    for (std::size_t i = 0; i < protocols.size(); ++i)
    {
        ASSERT_EQ(parsedProtos[i], protocols[i]);
    }
}

TEST_F(ALPNTest, SerializeFailsWhenBufferTooSmall)
{
    ALPN alpn("h2");
    std::vector<uint8_t> buffer(1);
    ASSERT_EQ(alpn.serialize(Side::Client, buffer), kSerializationFailed);
}

TEST_F(ALPNTest, ConstructorWithTooLongProtocolFails)
{
    std::string longProtocol(256, 'a');
    ASSERT_THROW(ALPN alpn(longProtocol), std::invalid_argument);
}