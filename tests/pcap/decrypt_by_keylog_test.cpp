
#include "decrypt_by_keylog_test.hpp"

#include <snet/tls.hpp>
#include <snet/layers/tcp_reassembly.hpp>

using namespace snet;
using namespace snet::tls;

class RecordChecker final : public tls::IRecordHandler
{
public:
    void handleRecord(const std::int8_t sideIndex, Session* session, Record* record) override
    {
        (void)sideIndex;
        (void)session;

        if (record->isDecrypted())
            decrypted = true;
    }

    bool decrypted{false};
};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData, void* userCookie)
{
    auto* test = static_cast<DecryptByKeylog*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = test->sessions_.find(tcpData.getConnectionData().flowKey);
        if (session == test->sessions_.end())
        {
            auto result = test->sessions_.emplace(
                std::make_pair(tcpData.getConnectionData().flowKey, std::make_shared<tls::Session>(test->recordPool_)));
            if (result.second)
            {
                session = result.first;
                session->second->setProcessor(test->processor_);
            }
        }

        if (session->second)
        {
            try
            {
                session->second->processRecords(sideIndex, {tcpData.getData(), tcpData.getDataLength()});
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
    , processor_(std::make_shared<tls::RecordHandlers>())
    , reassembler_(tcpReassemblyMsgReadyCallback, this)
{
    auto found = section.find("keylog");
    if (found != section.end())
        secretManager_.parseKeyLogFile(found->second);

    processor_->push_back(std::make_shared<tls::SnifferHandler>(secretManager_));
    processor_->push_back(std::make_shared<tls::RecordPrinter>());
    processor_->push_back(std::make_shared<RecordChecker>());
}

void DecryptByKeylog::execute()
{
    RecvStatus status{RecvStatus::Ok};
    snet::io::RawPacket* rawPacket{nullptr};
    do
    {
        status = driver_->receivePacket(&rawPacket);
        if (rawPacket)
        {
            reassembler_.reassemblePacket(rawPacket);
            driver_->finalizePacket(rawPacket, Verdict::Pass);
        }
    } while (status == RecvStatus::Ok);

    casket::utils::ThrowIfFalse(std::dynamic_pointer_cast<RecordChecker>((*processor_)[2])->decrypted,
                                "no one record decrypted");
}
