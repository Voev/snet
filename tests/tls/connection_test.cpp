#include <gtest/gtest.h>
#include <snet/tls.hpp>

#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/cert_authority.hpp>

using namespace snet::crypto;
using namespace snet::tls;

static constexpr std::size_t kDefaultBufferSize{4096};

TEST(HandshakeClientTest, NotEnoughOutputSize)
{
    std::vector<uint8_t> buffer;
    std::size_t bufferSize{0U};

    std::error_code ec;
    StateMachine client(std::move(ClientSettings()));

    // trying to read with small buffer
    ASSERT_EQ(Want::Output, client.handshake(nullptr, 0, buffer.data(), &bufferSize, ec));
    ASSERT_FALSE(ec);

    // resize small buffer and try again
    buffer.resize(bufferSize);
    ASSERT_EQ(Want::Nothing, client.handshake(nullptr, 0, buffer.data(), &bufferSize, ec));
    ASSERT_FALSE(ec);
}

TEST(HandshakeClientTest, FullReading)
{
    std::size_t bufferSize{::kDefaultBufferSize};
    std::vector<uint8_t> buffer(bufferSize);

    std::error_code ec;
    StateMachine client(std::move(ClientSettings()));

    // reading ClientHello record
    ASSERT_EQ(Want::Nothing, client.handshake(nullptr, 0, buffer.data(), &bufferSize, ec));
    ASSERT_FALSE(ec);

    // waiting for input
    ASSERT_EQ(Want::Input, client.handshake(nullptr, 0, buffer.data(), &bufferSize, ec));
    ASSERT_FALSE(ec);
}

class HandshakeServerTest : public testing::Test
{
public:
    HandshakeServerTest()
        : ca_("CN=Test Root CA")
    {
    }

    ~HandshakeServerTest() = default;

    void SetUp() override
    {
        auto serverKey = akey::rsa::generate(2048);
        auto serverCert = ca_.sign("CN=Test Server", serverKey.get());

        ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));
        ASSERT_NO_THROW(serverSettings_.useCertificate(serverCert.get()));
        ASSERT_NO_THROW(serverSettings_.usePrivateKey(serverKey.get()));
    }

    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    ServerSettings serverSettings_;
};

TEST_F(HandshakeServerTest, IncompleteInputBuffer)
{
    std::vector<uint8_t> buffer = {0x16, 0x03, 0x01, 0x00, 0x01};
    std::size_t bufferSize{buffer.size()};

    std::error_code ec;
    StateMachine server(serverSettings_);

    ASSERT_EQ(Want::Input, server.handshake(buffer.data(), bufferSize, nullptr, nullptr, ec));
    ASSERT_FALSE(ec);
}

TEST_F(HandshakeServerTest, UnexpectedMessageForClientHello)
{
    std::vector<uint8_t> buffer = {0x16, 0x03, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xC0, 0xDE};
    std::size_t bufferSize{buffer.size()};

    std::error_code ec;
    StateMachine server(serverSettings_);

    ASSERT_EQ(Want::Nothing, server.handshake(buffer.data(), bufferSize, nullptr, nullptr, ec));
    ASSERT_TRUE(ec);

    const auto& alert = server.getAlert();
    ASSERT_EQ(alert.isFatal(), true);
    ASSERT_EQ(alert.description(), Alert::UnexpectedMessage);
}

class HandshakeTest : public testing::Test
{
public:
    HandshakeTest()
        : ca_("CN=Test Root CA")
    {
    }
    ~HandshakeTest() = default;

    void SetUp() override
    {
        auto serverKey = akey::rsa::generate(2048);
        auto serverCert = ca_.sign("CN=Test Server", serverKey.get());

        ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));
        ASSERT_NO_THROW(serverSettings_.useCertificate(serverCert.get()));
        ASSERT_NO_THROW(serverSettings_.usePrivateKey(serverKey.get()));
    }
    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    ClientSettings clientCtx_;
    ServerSettings serverSettings_;
};

TEST_F(HandshakeTest, ReplyServerHelloForClientHello)
{
    std::error_code ec;

    size_t clientBufferSize{::kDefaultBufferSize};
    size_t serverBufferSize{::kDefaultBufferSize};

    std::vector<uint8_t> clientBuffer(clientBufferSize);
    std::vector<uint8_t> serverBuffer(serverBufferSize);

    StateMachine client(clientCtx_);
    ASSERT_EQ(Want::Nothing,
              client.handshake(nullptr, 0, clientBuffer.data(), &clientBufferSize, ec));
    ASSERT_FALSE(ec);

    StateMachine server(serverSettings_);
    ASSERT_EQ(Want::Nothing, server.handshake(clientBuffer.data(), clientBufferSize,
                                              serverBuffer.data(), &serverBufferSize, ec));
    ASSERT_FALSE(ec);
}

TEST_F(HandshakeTest, ReplyAlertForClientHello)
{
    std::error_code ec;

    size_t clientBufferSize{::kDefaultBufferSize};
    size_t serverBufferSize{::kDefaultBufferSize};

    std::vector<uint8_t> clientBuffer(clientBufferSize);
    std::vector<uint8_t> serverBuffer(serverBufferSize);

    ASSERT_NO_THROW(clientCtx_.setMinVersion(ProtocolVersion::TLSv1_3));
    ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));

    StateMachine client(clientCtx_);
    ASSERT_EQ(Want::Nothing,
              client.handshake(nullptr, 0, clientBuffer.data(), &clientBufferSize, ec));
    ASSERT_FALSE(ec);

    StateMachine server(serverSettings_);
    ASSERT_EQ(Want::Nothing, server.handshake(clientBuffer.data(), clientBufferSize,
                                              serverBuffer.data(), &serverBufferSize, ec));
    ASSERT_TRUE(ec);

    const auto& alert = server.getAlert();
    ASSERT_EQ(alert.isFatal(), true);
    ASSERT_EQ(alert.description(), Alert::ProtocolVersion);
}

TEST_F(HandshakeTest, PartialWriting)
{
    std::error_code ec;

    size_t clientBufferSize{::kDefaultBufferSize};
    size_t serverBufferSize{::kDefaultBufferSize};

    std::vector<uint8_t> clientBuffer(clientBufferSize);
    std::vector<uint8_t> serverBuffer(serverBufferSize);

    StateMachine client(clientCtx_);
    ASSERT_EQ(Want::Nothing,
              client.handshake(nullptr, 0, clientBuffer.data(), &clientBufferSize, ec));
    ASSERT_FALSE(ec);

    StateMachine server(serverSettings_);

    for (std::size_t i{0}; i < clientBufferSize; ++i)
    {
        if (i != clientBufferSize - 1)
        {
            ASSERT_EQ(Want::Input, server.handshake(&clientBuffer[i], 1, serverBuffer.data(),
                                                    &serverBufferSize, ec));
        }
        else
        {
            ASSERT_EQ(Want::Nothing, server.handshake(&clientBuffer[i], 1, serverBuffer.data(),
                                                      &serverBufferSize, ec));
        }
        ASSERT_FALSE(ec);
    }

    clientBufferSize = clientBuffer.size();
    ASSERT_EQ(Want::Nothing, client.handshake(serverBuffer.data(), serverBufferSize,
                                              clientBuffer.data(), &clientBufferSize, ec));
    ASSERT_FALSE(ec);
}

struct HandshakeProcessTestParam
{
    ProtocolVersion version;
};

class HandshakeProcessTest : public testing::TestWithParam<HandshakeProcessTestParam>
{
public:
    HandshakeProcessTest()
        : ca_("CN=Test Root CA")
    {
    }

    ~HandshakeProcessTest() = default;

    void SetUp() override
    {
        clientSettings_.setSecurityLevel(SecurityLevel::Level0);
        serverSettings_.setSecurityLevel(SecurityLevel::Level0);

        auto serverKey = akey::rsa::generate(2048);
        auto serverCert = ca_.sign("CN=Test Server", serverKey.get());

        ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));
        ASSERT_NO_THROW(serverSettings_.useCertificate(serverCert.get()));
        ASSERT_NO_THROW(serverSettings_.usePrivateKey(serverKey.get()));
    }

    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    ClientSettings clientSettings_;
    ServerSettings serverSettings_;
};

TEST_P(HandshakeProcessTest, IterativeHandshake)
{
    std::error_code ec;

    size_t clientBufferSize{::kDefaultBufferSize};
    size_t serverBufferSize{::kDefaultBufferSize};

    std::vector<uint8_t> clientBuffer(clientBufferSize);
    std::vector<uint8_t> serverBuffer(serverBufferSize);

    StateMachine client(clientSettings_);
    StateMachine server(serverSettings_);

    const auto& param = GetParam();
    ASSERT_NO_THROW(client.setVersion(param.version));
    ASSERT_NO_THROW(server.setVersion(param.version));

    serverBufferSize = 0;
    do
    {
        clientBufferSize = clientBuffer.size();
        ASSERT_EQ(Want::Nothing, client.handshake(serverBuffer.data(), serverBufferSize,
                                                  clientBuffer.data(), &clientBufferSize, ec));
        ASSERT_FALSE(ec);

        serverBufferSize = serverBuffer.size();
        ASSERT_EQ(Want::Nothing, server.handshake(clientBuffer.data(), clientBufferSize,
                                                  serverBuffer.data(), &serverBufferSize, ec));
        ASSERT_FALSE(ec);

    } while (!client.afterHandshake());

    ASSERT_TRUE(server.afterHandshake());
}

INSTANTIATE_TEST_SUITE_P(ParametrizedConnectionTests, HandshakeProcessTest,
                         testing::Values(HandshakeProcessTestParam{ProtocolVersion::TLSv1_0},
                                         HandshakeProcessTestParam{ProtocolVersion::TLSv1_1},
                                         HandshakeProcessTestParam{ProtocolVersion::TLSv1_2},
                                         HandshakeProcessTestParam{ProtocolVersion::TLSv1_3}));