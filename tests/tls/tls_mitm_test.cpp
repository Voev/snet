#include <gtest/gtest.h>
#include <snet/tls.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/rand.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/cert_forger.hpp>

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

        serverKey_ = RsaAsymmKey::generate(2048);
        serverCert_ = ca_.sign("CN=Test Server", serverKey_);

        ASSERT_NO_THROW(serverSettings_.setMaxVersion(ProtocolVersion::TLSv1_2));
        ASSERT_NO_THROW(serverSettings_.useCertificate(serverCert_));
        ASSERT_NO_THROW(serverSettings_.usePrivateKey(serverKey_));

        certForger_ = std::make_unique<CertForger>(ca_.getKey(), ca_.getCert());
    }

    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    ClientSettings clientSettings_;
    ServerSettings serverSettings_;
    KeyPtr serverKey_;
    X509CertPtr serverCert_;
    std::unique_ptr<CertForger> certForger_;
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
    //mitmClient.setDebugKeys(true);

    Session mitmServer(recordPool);
    mitmServer.setDebugKeys(true);

    auto mitmKey = RsaAsymmKey::generate(2048);
    auto mitmCert = certForger_->resign(mitmKey, serverCert_);

    mitmServer.setServerKey(mitmKey);
    mitmServer.setCertificate(1, std::move(mitmCert));

    do
    {
        clientBufferSize = clientBuffer.size();
        ASSERT_EQ(Want::Nothing,
                  client.handshake(serverBuffer.data(), serverBufferSize, clientBuffer.data(), &clientBufferSize, ec));
        ASSERT_FALSE(ec) << ec.message();

        std::cout << "MITM SERVER:" << std::endl;
        ASSERT_EQ(clientBufferSize, mitmServer.readRecords({clientBuffer.data(), clientBufferSize}));

        snet::utils::printHex(std::cout, {clientBuffer.data(), clientBufferSize}, "Before MITM client:");

        mitmServer.processPendingRecords(
            0,
            [&recordPool, &mitmClient](const int8_t sideIndex, Record* record)
            {
                auto modifiedRecord = recordPool.acquire();

                if (record->getType() == RecordType::Handshake)
                {
                    switch (record->getHandshakeType())
                    {
                    case HandshakeType::ClientHelloCode:
                    {
                        ClientHello clientHello = record->getHandshake<ClientHello>();

                        mitmClient.processClientHello(clientHello,
                                                      [](Session* session, Extensions& extensions)
                                                      {
                                                          if (extensions.has(ExtensionCode::KeyShare))
                                                          {
                                                              auto keyShare = extensions.take<KeyShare>();
                                                              auto offeredGroups = keyShare->offeredGroups();
                                                              auto firstGroup = offeredGroups.front();

                                                              /// @todo: check offered group by policy

                                                              auto key = GroupParams::generateKeyByParams(firstGroup);
                                                              keyShare->setPublicKey(0, key);
                                                              session->setEphemeralPrivateKey(std::move(key));
                                                              extensions.add(std::move(keyShare));
                                                          }
                                                      });

                        modifiedRecord->serializeHandshake(
                            HandshakeMessage(std::move(clientHello), HandshakeType::ClientHelloCode), sideIndex,
                            mitmClient);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                    }

                    mitmClient.postprocessRecord(sideIndex, modifiedRecord);
                    mitmClient.addOutgoingRecord(sideIndex, modifiedRecord);
                }
            });

        clientBufferSize = mitmClient.writeRecords(clientBuffer);
        snet::utils::printHex(std::cout, {clientBuffer.data(), clientBufferSize}, "After MITM client:");

        serverBufferSize = serverBuffer.size();
        ASSERT_EQ(Want::Nothing,
                  server.handshake(clientBuffer.data(), clientBufferSize, serverBuffer.data(), &serverBufferSize, ec));
        ASSERT_FALSE(ec) << ec.message();

        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize}, "Before MITM server:");

        std::cout << "MITM CLIENT:" << std::endl;

        ASSERT_EQ(serverBufferSize, mitmClient.readRecords({serverBuffer.data(), serverBufferSize}));
        mitmClient.processPendingRecords(
            1,
            [&recordPool, &mitmServer](const int8_t sideIndex, Record* record)
            {
                /// 1. Modify
                /// 2. Process
                /// 3. Serialize
                /// 4. Update hash (for handshake)
                /// 5. Encryption (optional)

                auto modifiedRecord = recordPool.acquire();

                if (record->getType() == RecordType::Handshake)
                {
                    switch (record->getHandshakeType())
                    {
                    case HandshakeType::ServerHelloCode:
                    {
                        ServerHello serverHello = record->getHandshake<ServerHello>();

                        std::cout << "MITM Server processing ServerHello:" << std::endl;
                        mitmServer.processServerHello(serverHello,
                                                      [](Session* session, Extensions& extensions)
                                                      {
                                                          if (extensions.has(ExtensionCode::KeyShare))
                                                          {
                                                              auto keyShare = extensions.take<KeyShare>();
                                                              auto offeredGroups = keyShare->offeredGroups();
                                                              auto firstGroup = offeredGroups.front();

                                                              auto clientKeyShare =
                                                                  session->getClientExtensions().get<KeyShare>();
                                                              auto peerKey = clientKeyShare->getPublicKey();
                                                              session->setPublicPeerKey(std::move(peerKey));

                                                              auto key = GroupParams::generateKeyByParams(firstGroup);
                                                              keyShare->setPublicKey(key);

                                                              session->setEphemeralPrivateKey(std::move(key));
                                                              extensions.add(std::move(keyShare));
                                                          }
                                                      });

                        
                        std::cout << "MITM Server processed ServerHello:" << std::endl;

                        modifiedRecord->serializeHandshake(
                            HandshakeMessage(std::move(serverHello), HandshakeType::ServerHelloCode), sideIndex,
                            mitmServer);
                        break;
                    }
                    case HandshakeType::EncryptedExtensionsCode:
                    {
                        EncryptedExtensions encryptedExtensions = record->getHandshake<EncryptedExtensions>();

                        mitmServer.processEncryptedExtensions(encryptedExtensions);

                        modifiedRecord->serializeHandshake(
                            HandshakeMessage(std::move(encryptedExtensions), HandshakeType::EncryptedExtensionsCode),
                            sideIndex, mitmServer);
                        break;
                    }
                    case HandshakeType::CertificateCode:
                    {
                        mitmServer.constructCertificate(sideIndex, modifiedRecord);
                        break;
                    }
                    case HandshakeType::CertificateVerifyCode:
                    {
                        mitmServer.constructCertificateVerify(sideIndex, modifiedRecord);
                        break;
                    }
                    case HandshakeType::FinishedCode:
                    {
                        Finished finished = record->getHandshake<Finished>();

                        modifiedRecord->serializeHandshake(
                            HandshakeMessage(std::move(finished), HandshakeType::FinishedCode),
                            sideIndex, mitmServer);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                    } /// switch

                    mitmServer.postprocessRecord(sideIndex, modifiedRecord);
                    mitmServer.addOutgoingRecord(sideIndex, modifiedRecord);
                }
                else if (record->getType() == RecordType::ApplicationData)
                {
                    /// write decrypted data...
                }
            });

        serverBufferSize = mitmServer.writeRecords(serverBuffer);
        snet::utils::printHex(std::cout, {serverBuffer.data(), serverBufferSize}, "After MITM server:");

    } while (!client.afterHandshake());

    ASSERT_TRUE(server.afterHandshake());
}

INSTANTIATE_TEST_SUITE_P(TLSMitmTests, TLSMitmTest, testing::Values(TLSMitmTestParam{ProtocolVersion::TLSv1_3}));