#include <gtest/gtest.h>
#include <snet/tls.hpp>

#include <snet/crypto/rand.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/cert_authority.hpp>

#include <snet/utils/print_hex.hpp>

using namespace snet::crypto;
using namespace snet::tls;

static constexpr std::size_t kDefaultBufferSize{4096};

struct TLSMitmTestParam
{
    ProtocolVersion version;
};

class TLSMitmTest : public testing::TestWithParam<TLSMitmTestParam>
{
public:
    TLSMitmTest()
        : ca_(RsaAsymmKey::generate(2048), "CN=Test Root CA")
    {
    }

    ~TLSMitmTest() = default;

    void SetUp() override
    {
        clientSettings_.setSecurityLevel(SecurityLevel::Level0);
        serverSettings_.setSecurityLevel(SecurityLevel::Level0);

        auto serverKey = RsaAsymmKey::generate(2048);
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

class MITMRecordHandler : public IRecordHandler
{
public:
    void handleClientHello(const ClientHello& clientHello, Session* session) override
    {
        ClientHello modified = clientHello;

        (void)modified;
        (void)session;

        //Record* record{nullptr};

        //record= session->acquireRecord();

        //record->serializeClientHello(modified);
    }

};

TEST_P(TLSMitmTest, IterativeHandshake)
{
    std::error_code ec;

    size_t clientBufferSize{::kDefaultBufferSize};
    size_t serverBufferSize{::kDefaultBufferSize};
    size_t mitmBufferSize{::kDefaultBufferSize};

    std::vector<uint8_t> clientBuffer(clientBufferSize);
    std::vector<uint8_t> serverBuffer(serverBufferSize);
    std::vector<uint8_t> mitmBuffer(mitmBufferSize);

    StateMachine client(clientSettings_);
    StateMachine server(serverSettings_);

    const auto& param = GetParam();
    ASSERT_NO_THROW(client.setVersion(param.version));
    ASSERT_NO_THROW(server.setVersion(param.version));

    serverBufferSize = 0;

    RecordPool recordPool(64);
    RecordProcessor proc(std::make_shared<RecordHandlers>());
    
    proc->push_back(std::make_shared<RecordPrinter>());
    
    Session mitmClient(recordPool);
    Session mitmServer(recordPool);

    do
    {
        clientBufferSize = clientBuffer.size();
        ASSERT_EQ(Want::Nothing,
                  client.handshake(serverBuffer.data(), serverBufferSize, clientBuffer.data(), &clientBufferSize, ec));
        ASSERT_FALSE(ec);

        ASSERT_EQ(clientBufferSize, mitmServer.readRecords({clientBuffer.data(), clientBufferSize}));

        snet::utils::printHex(std::cout, {clientBuffer.data(), clientBufferSize});

        mitmServer.processPendingRecords(0, [&clientBufferSize, &clientBuffer, &recordPool, &mitmClient](const int8_t sideIndex, Record* record) {
            
            (void)sideIndex;
            
            auto modifiedRecord = recordPool.acquireScoped();

            switch(record->getHandshakeType())
            {
                case HandshakeType::ClientHelloCode:
                {
                    ClientHello clientHello = record->getHandshake<ClientHello>();

                    mitmClient.processClientHello(clientHello);

                    /// mitmClient перегенерирует KeyShare на основе того GroupParams который уже есть

                    uint8_t random[32] = {};
                    Rand::generate(random);

                    clientHello.random = random;
                    /// filter ciphersuites
                    /// filter extensions

                    mitmClient.generateKeyShare();

                    nonstd::span<uint8_t> out = clientBuffer;
                    clientBufferSize = modifiedRecord->serializeClientHello(clientHello, out.subspan(TLS_HEADER_SIZE), mitmClient);
                    clientBufferSize += modifiedRecord->serializeHeader(out.subspan(0, TLS_HEADER_SIZE));
                    break;
                }
                default:
                {
                    break;
                }
            }
        } );

        snet::utils::printHex(std::cout, {clientBuffer.data(), clientBufferSize}, "Modified:");

        serverBufferSize = serverBuffer.size();
        ASSERT_EQ(Want::Nothing,
                  server.handshake(clientBuffer.data(), clientBufferSize, serverBuffer.data(), &serverBufferSize, ec));
        ASSERT_FALSE(ec);

        ASSERT_EQ(serverBufferSize, mitmClient.readRecords({serverBuffer.data(), serverBufferSize}));
        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize});

        serverBufferSize = 0;

        mitmClient.processPendingRecords(1, [&serverBufferSize, &serverBuffer, &recordPool, &mitmServer](const int8_t sideIndex, Record* record) {
            
            (void)sideIndex;
            
            auto modifiedRecord = recordPool.acquireScoped();

            switch(record->getHandshakeType())
            {
                case HandshakeType::ServerHelloCode:
                {
                    ServerHello serverHello = record->getHandshake<ServerHello>();

                    uint8_t random[32] = {};
                    Rand::generate(random);

                    serverHello.random = random; 
                    /// filter ciphersuite
                    /// filter extensions

                    /// mitmClient перегенерирует KeyShare на основе того GroupParams который уже есть

                    mitmServer.generateServerKeyShare();

                    nonstd::span<uint8_t> out = serverBuffer;
                    serverBufferSize += modifiedRecord->serializeServerHello(serverHello, out.subspan(TLS_HEADER_SIZE), mitmServer);
                    serverBufferSize += modifiedRecord->serializeHeader(out.subspan(0, TLS_HEADER_SIZE));
                    break;
                }
                case HandshakeType::EncryptedExtensionsCode:
                {
                    EncryptedExtensions encryptedExtensions = record->getHandshake<EncryptedExtensions>();

                    // задаем в plaintext_
                    // сериализуем сразу в plaintext_
                    serverBufferSize += modifiedRecord->serializeEncryptedExtensions(encryptedExtensions, mitmServer);
                    // шифруем в ciphertext_
                    mitmServer.sealHandshakeRecord(1, modifiedRecord.get());
                }
                default:
                {
                    break;
                }
            }
        } );

        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize}, "After MITM server:");

    } while (!client.afterHandshake());

    ASSERT_TRUE(server.afterHandshake());
}

INSTANTIATE_TEST_SUITE_P(TLSMitmTests, TLSMitmTest,
                         testing::Values(TLSMitmTestParam{ProtocolVersion::TLSv1_3}));