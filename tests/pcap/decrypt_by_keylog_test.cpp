
#include "decrypt_by_keylog_test.hpp"

#include <snet/tls.hpp>
#include <snet/layers/l4/tcp_reassembly.hpp>

#include <casket/utils/string.hpp>
#include <casket/utils/to_number.hpp>

using namespace snet;
using namespace snet::tcp;
using namespace snet::tls;
using namespace casket;

DecryptByKeylog::DecryptByKeylog(const ConfigParser::Section& section)
    : rxPool_(512, 64 * 1024)
    , recordPool_(256)
{
    auto found = section.find("keylog");
    if (found != section.end())
    {
        secretManager_.parseKeyLogFile(found->second);
    }

    TlsDecryptOptions options;
    found = section.find("print_records");
    if (found != section.end() && iequals(found->second, "yes"))
    {
        options.printRecords = true;
    }

    found = section.find("decrypted_records_count");
    ThrowIfTrue(found == section.end(), "not found required option 'decrypted_records_count'");
    to_number(found->second, expectedDecryptedRecordCount_);

    consumer_ = std::make_unique<TlsDecryptStreamConsumer<SessionManager>>(&sessionManager_, &secretManager_, options);
    auto receiver = std::make_shared<TcpReceiveHandler<SessionManager>>(&rxPool_, nullptr, consumer_.get());
    auto decryption = std::make_shared<TlsDecryptHandler<SessionManager>>(&recordPool_);
    
    auto pipeline = std::make_unique<SessionManager::Pipeline>();
    pipeline->add(receiver);
    pipeline->add(decryption);
    sessionManager_.setPipeline(std::move(pipeline));
}

void DecryptByKeylog::execute()
{
    RecvStatus status{RecvStatus::Ok};
    snet::layers::Packet* packets[32] = {};
    uint16_t maxCount = 32;
    uint16_t receivedPackets = 0;

    do
    {
        status = driver_->receivePackets(packets, &receivedPackets, maxCount);
        for (uint16_t i = 0; i < receivedPackets; ++i)
        {
            snet::layers::Packet* packet = packets[i];
            if (packet)
            {
                packet->parse();
                sessionManager_.processPacket(packet);
                driver_->finalizePacket(packet, Verdict::Pass);
            }
        }
    } while (status == RecvStatus::Ok);

    auto stats = consumer_->getStats();
    casket::ThrowIfFalse(stats.decryptedRecords == expectedDecryptedRecordCount_,
                         "actual: {}, expected: {}; mismatch decrypted records", stats.decryptedRecords,
                         expectedDecryptedRecordCount_);
}
