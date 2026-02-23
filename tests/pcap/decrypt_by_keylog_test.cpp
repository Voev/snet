
#include "decrypt_by_keylog_test.hpp"

#include <snet/tls.hpp>
#include <snet/layers/l4/tcp_reassembly.hpp>

#include <casket/utils/string.hpp>
#include <casket/utils/to_number.hpp>

using namespace snet;
using namespace snet::tls;
using namespace casket;

class RecordChecker final : public tls::IRecordHandler
{
public:
    void handleRecord(const std::int8_t sideIndex, Session* session, Record* record) override
    {
        (void)sideIndex;
        (void)session;

        if (record->isPlaintext())
        {
            decryptedRecordCount += 1;
        }
    }

    size_t decryptedRecordCount{0};
};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const layers::TcpStreamData& tcpData, void* userCookie)
{
    auto* test = static_cast<DecryptByKeylog*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = test->sessions_.find(tcpData.getConnectionData().flowKey);
        if (session == test->sessions_.end())
        {
            auto flowKey = tcpData.getConnectionData().flowKey;
            auto result =
                test->sessions_.emplace(std::make_pair(flowKey, std::make_shared<Session>(test->recordPool_)));
            if (result.second)
            {
                session = result.first;
            }
        }

        if (session->second)
        {
            try
            {
                auto state = session->second;
                state->readRecords({tcpData.getData(), tcpData.getDataLength()});
                state->processPendingRecords(sideIndex,
                                             [&test, &state](const int8_t sideIndex, Record* record)
                                             {
                                                 if (test->printRecords_)
                                                 {
                                                     PrintRecord(sideIndex, state.get(), record);
                                                 }

                                                 if (record->getHandshakeType() == HandshakeType::ClientHelloCode)
                                                 {
                                                     auto& clientHello = record->getHandshake<ClientHello>();
                                                     ClientRandom random{clientHello.random.begin(),
                                                                         clientHello.random.end()};
                                                     auto secrets = test->secretManager_.getSecretNode(random);
                                                     if (secrets)
                                                     {
                                                         state->setSecrets(secrets);
                                                     }
                                                 }

                                                 if (record->isPlaintext())
                                                 {
                                                     test->actualDecryptedRecordCount_ += 1;
                                                 }
                                             });
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error processing payload with length " << tcpData.getDataLength() << ": " << e.what()
                          << '\n';
            }
        }
    }
}

DecryptByKeylog::DecryptByKeylog(const ConfigParser::Section& section)
    : recordPool_(1024)
    , reassembler_(tcpReassemblyMsgReadyCallback, this)
{
    auto found = section.find("keylog");
    if (found != section.end())
    {
        secretManager_.parseKeyLogFile(found->second);
    }

    found = section.find("print_records");
    if (found != section.end() && iequals(found->second, "yes"))
    {
        printRecords_ = true;
    }

    found = section.find("decrypted_records_count");
    ThrowIfTrue(found == section.end(), "not found required option 'decrypted_records_count'");
    to_number(found->second, expectedDecryptedRecordCount_);
}

void DecryptByKeylog::execute()
{
    RecvStatus status{RecvStatus::Ok};
    snet::layers::Packet* packet{nullptr};
    do
    {
        status = driver_->receivePacket(&packet);
        if (packet)
        {
            packet->parsePacket(layers::TCP);
            reassembler_.reassemblePacket(packet);
            driver_->finalizePacket(packet, Verdict::Pass);
        }
    } while (status == RecvStatus::Ok);

    casket::ThrowIfFalse(actualDecryptedRecordCount_ == expectedDecryptedRecordCount_,
                         "actual: {}, expected: {}; mismatch decrypted records", actualDecryptedRecordCount_,
                         expectedDecryptedRecordCount_);
}
