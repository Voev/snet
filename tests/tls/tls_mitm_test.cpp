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

        // Record* record{nullptr};

        // record= session->acquireRecord();

        // record->serializeClientHello(modified);
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

        mitmServer.processPendingRecords(
            0,
            [&clientBufferSize, &clientBuffer, &recordPool, &mitmClient](const int8_t sideIndex, Record* record)
            {
                (void)sideIndex;

                auto modifiedRecord = recordPool.acquireScoped();

                /// 1. Serialization
                /// 2. Update hash
                /// 3. Encryption

                switch (record->getHandshakeType())
                {
                case HandshakeType::ClientHelloCode:
                {
                    ClientHello clientHello = record->getHandshake<ClientHello>();
                    mitmClient.constructClientHello(clientHello);

                    nonstd::span<uint8_t> out = clientBuffer;
                    clientBufferSize =
                        modifiedRecord->serializeClientHello(clientHello, out.subspan(TLS_HEADER_SIZE), mitmClient);
                    mitmClient.updateData({out.subspan(TLS_HEADER_SIZE).data(), clientBufferSize});
                    clientBufferSize += modifiedRecord->serializeHeader(out.subspan(0, TLS_HEADER_SIZE));
                    break;
                }
                default:
                {
                    break;
                }
                }
            });

        snet::utils::printHex(std::cout, {clientBuffer.data(), clientBufferSize}, "After MITM client:");

        serverBufferSize = serverBuffer.size();
        ASSERT_EQ(Want::Nothing,
                  server.handshake(clientBuffer.data(), clientBufferSize, serverBuffer.data(), &serverBufferSize, ec));
        ASSERT_FALSE(ec);

        ASSERT_EQ(serverBufferSize, mitmClient.readRecords({serverBuffer.data(), serverBufferSize}));
        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize});

        serverBufferSize = 0;

        mitmClient.processPendingRecords(
            1,
            [&serverBufferSize, &serverBuffer, &recordPool, &mitmServer](const int8_t sideIndex, Record* record)
            {
                /// 1. Modify
                /// 2. Process
                /// 3. Serialize
                /// 4. Update hash (for handshake)
                /// 5. Encryption (optional)

                auto modifiedRecord = recordPool.acquire();

                if (record->getType() == RecordType::Handshake)
                {
                    HandshakeMessage handshake;

                    switch (record->getHandshakeType())
                    {
                    case HandshakeType::ServerHelloCode:
                    {
                        /// 1. Modify
                        ServerHello serverHello = record->getHandshake<ServerHello>();

                        mitmServer.processServerHello(serverHello,
                                                      [](Session* session, Extensions& extensions)
                                                      {
                                                          if (extensions.has(ExtensionCode::KeyShare))
                                                          {
                                                              auto keyShare = extensions.take<KeyShare>();
                                                              auto offeredGroups = keyShare->offeredGroups();
                                                              auto firstGroup = offeredGroups.front();

                                                              auto key = GroupParams::generateKeyByParams(firstGroup);
                                                              keyShare->setPublicKey(key);

                                                              session->setEphemeralServerKey(std::move(key));
                                                              extensions.add(std::move(keyShare));
                                                          }
                                                      });

                        handshake = HandshakeMessage(std::move(serverHello), HandshakeType::ServerHelloCode);
                        break;
                    }
                    case HandshakeType::EncryptedExtensionsCode:
                    {
                        EncryptedExtensions encryptedExtensions = record->getHandshake<EncryptedExtensions>();
                        mitmServer.processEncryptedExtensions(encryptedExtensions);
                        handshake =
                            HandshakeMessage(std::move(encryptedExtensions), HandshakeType::EncryptedExtensionsCode);
                        ;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                    } /// switch

                    /// 3. serialize (handshake)
                    modifiedRecord->serializeHandshake(std::move(handshake), mitmServer);

                    /// 4. update hash (handshake) - here???
                    mitmServer.postprocessRecord(sideIndex, modifiedRecord);

                    /// 5. encryption (optional)
                    if (mitmServer.canDecrypt(sideIndex))
                    {
                        mitmServer.encrypt(sideIndex, modifiedRecord);
                    }

                    mitmServer.addOutgoingRecord(modifiedRecord);
                }
                else if (record->getType() == RecordType::ApplicationData)
                {
                    /// write decrypted data...
                }
            });

        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize}, "After MITM server:");

    } while (!client.afterHandshake());

    ASSERT_TRUE(server.afterHandshake());
}

INSTANTIATE_TEST_SUITE_P(TLSMitmTests, TLSMitmTest, testing::Values(TLSMitmTestParam{ProtocolVersion::TLSv1_3}));