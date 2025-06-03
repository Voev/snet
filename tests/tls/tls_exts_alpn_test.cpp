#include <gtest/gtest.h>
#include <snet/tls/exts/alpn.hpp>
#include <casket/utils/exception.hpp>

using namespace snet::tls;
using namespace snet::utils;
using namespace casket::utils;

class ALPNTest : public ::testing::Test
{
};

TEST_F(ALPNTest, ConstructorWithSingleProtocol)
{
    ALPN alpn("http/1.1");
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.protocols().size(), 1);
    ASSERT_EQ(alpn.protocols()[0], "http/1.1");
    ASSERT_EQ(alpn.singleProtocol(), "http/1.1");
}

TEST_F(ALPNTest, ConstructorWithProtocolList)
{
    std::vector<std::string> protocols = {"http/1.1", "h2", "h3"};

    ALPN alpn(protocols);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.protocols().size(), 3);
    ASSERT_EQ(alpn.protocols(), protocols);
}

TEST_F(ALPNTest, ParseFromReaderClientSide)
{
    std::vector<uint8_t> data = {0x00, 0x0C, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    ALPN alpn(Side::Client, data);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.protocols().size(), 2);
    ASSERT_EQ(alpn.protocols()[0], "h2");
    ASSERT_EQ(alpn.protocols()[1], "http/1.1");
}

TEST_F(ALPNTest, ParseFromReaderServerSide)
{
    std::vector<uint8_t> data = {0x00, 0x03, 0x02, 'h', '2'};

    ALPN alpn(Side::Server, data);
    ASSERT_FALSE(alpn.empty());
    ASSERT_EQ(alpn.protocols().size(), 1);
    ASSERT_EQ(alpn.protocols()[0], "h2");
}

TEST_F(ALPNTest, ParseEmptyExtension)
{
    ASSERT_THROW(ALPN alpn(Side::Client, {}), RuntimeError);
}

TEST_F(ALPNTest, ParseThrowsOnInvalidLength)
{
    std::vector<uint8_t> data = {0x00, 0x05, 0x02, 'h', '2'};

    ASSERT_THROW(ALPN alpn(Side::Client, data), RuntimeError);
}

TEST_F(ALPNTest, ParseThrowsOnEmptyProtocol)
{
    std::vector<uint8_t> data = {0x00, 0x01, 0x00};

    ASSERT_THROW(ALPN alpn(Side::Client, data), RuntimeError);
}

TEST_F(ALPNTest, ParseThrowsWhenServerSendsMultipleProtocols)
{
    std::vector<uint8_t> data = {0x00, 0x05, 0x02, 'h', '2', 0x02, 'h', '3'};

    ASSERT_THROW(ALPN alpn(Side::Server, data), RuntimeError);
}

TEST_F(ALPNTest, SerializeSingleProtocol)
{
    std::vector<uint8_t> buffer(32);

    ALPN alpn("h2");
    size_t written = alpn.serialize(Side::Client, buffer);
    ASSERT_GT(written, 0);
    buffer.resize(written);

    ALPN parsed(Side::Client, buffer);
    ASSERT_EQ(parsed.singleProtocol(), "h2");
}

TEST_F(ALPNTest, SerializeMultipleProtocols)
{
    std::vector<std::string> protocols = {"http/1.1", "h2", "h3"};

    ALPN alpn(protocols);
    std::vector<uint8_t> buffer(32);

    size_t written = alpn.serialize(Side::Client, buffer);
    ASSERT_GT(written, 0);
    buffer.resize(written);

    ASSERT_GT(written, 0);
    ALPN parsed(Side::Client, buffer);

    ASSERT_EQ(parsed.protocols(), protocols);
}

TEST_F(ALPNTest, SerializeThrowsWhenBufferTooSmall)
{
    ALPN alpn("h2");
    std::vector<uint8_t> buffer(1);
    ASSERT_THROW(alpn.serialize(Side::Client, buffer), RuntimeError);
}

TEST_F(ALPNTest, SerializeThrowsWhenProtocolTooLong)
{
    std::string longProtocol(256, 'a');

    ALPN alpn(longProtocol);
    std::vector<uint8_t> buffer(512);
    ASSERT_THROW(alpn.serialize(Side::Client, buffer), RuntimeError);
}
