#include <gtest/gtest.h>
#include <snet/tls.hpp>

#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/cert_authority.hpp>

using namespace snet::crypto;
using namespace snet::tls;

static constexpr std::size_t kDefaultBufferSize{4096};


struct TlsSpooferTestParam
{
    ProtocolVersion version;
};

class TlsSpooferTest : public testing::TestWithParam<TlsSpooferTestParam>
{
public:
    TlsSpooferTest()
        : ca_("CN=Test Root CA")
    {
    }

    ~TlsSpooferTest() = default;

    void SetUp() override
    {
        clientSettings_.setSecurityLevel(SecurityLevel::Level0);

        serverSettings_.setSecurityLevel(SecurityLevel::Level0);
        serverSettings_.setKeyLog();

        auto serverKey = akey::rsa::generate(2048);
        auto serverCert = ca_.sign("CN=Test Server", serverKey.get());

        ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));
        ASSERT_NO_THROW(serverSettings_.useCertificate(serverCert.get()));
        ASSERT_NO_THROW(serverSettings_.usePrivateKey(serverKey.get()));

        ASSERT_NO_THROW(spoofer_.addHandler<RecordDecryptor>());
        ASSERT_NO_THROW(spoofer_.addHandler<RecordPrinter>());
        ASSERT_NO_THROW(spoofer_.addHandler<RecordEncryptor>(spoofer_.getRecordPool()));
    }

    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    ClientSettings clientSettings_;
    ServerSettings serverSettings_;
    RecordProcessor spoofer_;
};

TEST_P(TlsSpooferTest, IterativeHandshake)
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

    auto session = std::make_unique<Session>(spoofer_.getRecordPool());

    serverBufferSize = 0;
    session->sendingLength = 0;
    do
    {
        clientBufferSize = clientBuffer.size();
        ASSERT_EQ(Want::Nothing, client.handshake(session->sendingBuffer, session->sendingLength,
                                                  clientBuffer.data(), &clientBufferSize, ec));
        ASSERT_FALSE(ec) << ec.message();

        spoofer_.process(0, session.get(), clientBuffer.data(), clientBufferSize);

        serverBufferSize = serverBuffer.size();
        ASSERT_EQ(Want::Nothing, server.handshake(session->sendingBuffer, session->sendingLength,
                                                  serverBuffer.data(), &serverBufferSize, ec));
        ASSERT_FALSE(ec) << ec.message();

        spoofer_.process(1, session.get(), serverBuffer.data(), serverBufferSize);

    } while (!client.afterHandshake());

    ASSERT_TRUE(server.afterHandshake());
}

INSTANTIATE_TEST_SUITE_P(ParametrizedSpooferTests, TlsSpooferTest,
                         testing::Values(//TlsSpooferTestParam{ProtocolVersion::TLSv1_0},
                                         //TlsSpooferTestParam{ProtocolVersion::TLSv1_1},
                                         //TlsSpooferTestParam{ProtocolVersion::TLSv1_2},
                                         TlsSpooferTestParam{ProtocolVersion::TLSv1_3}));