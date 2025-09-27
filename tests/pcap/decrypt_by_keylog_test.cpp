
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

        if (record->isDecrypted())
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
    {
        secretManager_.parseKeyLogFile(found->second);
    }

    processor_->push_back(std::make_shared<tls::SnifferHandler>(secretManager_));
    processor_->push_back(std::make_shared<RecordChecker>());

    found = section.find("print_records");
    if (found != section.end() && iequals(found->second, "yes"))
    {
        processor_->push_back(std::make_shared<tls::RecordPrinter>());
    }

    found = section.find("decrypted_records_count");
    ThrowIfTrue(found == section.end(), "not found required option 'decrypted_records_count'");
    to_number(found->second, decryptedRecordCount_);
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

    auto count = std::dynamic_pointer_cast<RecordChecker>((*processor_)[1])->decryptedRecordCount;
    casket::ThrowIfFalse(count == decryptedRecordCount_, "actual: {}, expected: {}; mismatch decrypted records", count,
                         decryptedRecordCount_);
}
