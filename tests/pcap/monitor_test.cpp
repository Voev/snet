
#include "monitor_test.hpp"

#include <snet/tls.hpp>
#include <snet/tcp/tcp_conn_ctx_factory.hpp>

#include <casket/utils/string.hpp>
#include <casket/utils/to_number.hpp>

using namespace snet;
using namespace snet::tcp;
using namespace snet::tls;
using namespace casket;

constexpr size_t kRxPoolCapacity = 128;
constexpr size_t kRxPoolBufferSize = 16 * 1024;
constexpr size_t kRecordPoolSize = 64;
constexpr size_t kPacketBatchSize = 32;

MonitorTest::MonitorTest(const ConfigParser::Section& section)
    : rxPool_(kRxPoolCapacity, kRxPoolBufferSize)
    , recordPool_(kRecordPoolSize)
    , expectedProcessedRecords_(0)
{
    MonitorOptions options;
    auto found = section.find("print_records");
    if (found != section.end() && iequals(found->second, "yes"))
    {
        options.printRecords = true;
    }

    found = section.find("processed_records_count");
    ThrowIfTrue(found == section.end(), "not found required option 'decrypted_records_count'");
    to_number(found->second, expectedProcessedRecords_);

    TcpReceiveHandlerConfig config;
    config.replayMode = true;

    consumer_ = std::make_unique<MonitorTlsStreamConsumer<SessionManager>>(&sessionManager_, options);
    auto receiver = std::make_shared<TcpReceiveHandler<SessionManager>>(nullptr, consumer_.get(), config);

    auto fRegistry = std::make_unique<SessionManager::FactoryRegistry>();
    fRegistry->addFactory<TcpConnectionCtxFactory<SessionManager>>(&rxPool_, nullptr);
    fRegistry->addFactory<TlsDecryptCtxFactory<SessionManager>>(&recordPool_, true);
    sessionManager_.setFactoryRegistry(std::move(fRegistry));

    auto pipeline = std::make_unique<SessionManager::Pipeline>();
    pipeline->add(receiver);
    sessionManager_.setPipeline(std::move(pipeline));
}

void MonitorTest::execute()
{
    RecvStatus status{RecvStatus::Ok};
    constexpr uint16_t maxCount = 32;
    snet::io::Driver::RxItem rx[maxCount] = {};
    uint16_t receivedPackets = 0;

    do
    {
        status = driver_->receivePackets(rx, &receivedPackets, maxCount);
        for (uint16_t i = 0; i < receivedPackets; ++i)
        {
            snet::layers::Packet* packet = rx[i].packet;
            if (packet)
            {
                packet->parse();
                sessionManager_.processPacket(packet);
                driver_->finalizePacket(packet, Verdict::Pass);
            }
        }
    } while (status == RecvStatus::Ok);

    auto stats = consumer_->getStats();
    casket::ThrowIfFalse(stats.processedRecords == expectedProcessedRecords_,
                         "actual: {}, expected: {}; mismatch processed records", stats.processedRecords,
                         expectedProcessedRecords_);
}
