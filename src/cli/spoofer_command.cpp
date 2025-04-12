#include <iostream>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_parser.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/error_code.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/cli/command_dispatcher.hpp>
#include <snet/crypto/asymm_key.hpp>

#include <snet/layers.hpp>
#include <snet/io.hpp>
#include <snet/tls.hpp>

#include <snet/utils/print_hex.hpp>

using namespace casket;
using namespace casket::log;

namespace snet::spoofer
{

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
    std::string driverPath;
};

struct Spoofy
{
    Spoofy()
        : client(tls::ClientSettings())
        , server(tls::ServerSettings())
        , ciphertext(16 * 1024)
        , plaintext(16 * 1024)
    {
    }

    tls::StateMachine client;
    tls::StateMachine server;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
};

using SessionManager = std::unordered_map<uint32_t, std::shared_ptr<Spoofy>>;

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData,
                                   void* userCookie)
{
    auto manager = static_cast<SessionManager*>(userCookie);
    (void)sideIndex;
    if (tcpData.getMissingByteCount() == 0)
    {
        auto flowKey = tcpData.getConnectionData().flowKey;
        auto session = manager->find(flowKey);
        if (session == manager->end())
        {
            auto result = manager->emplace(std::make_pair(flowKey, std::make_shared<Spoofy>()));
            if (result.second)
            {
                session = result.first;
            }
        }
    }
}

class Command final : public cmd::Command
{
public:
    Command()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("input, i", opt::Value(&options_.input), "Input PCAP file");
        parser_.add("driver, d", opt::Value(&options_.driverPath), "Driver path");
    }

    ~Command() = default;

    void execute(const std::vector<std::string_view>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout);
            return;
        }

        LogManager::Instance().enable(Type::Console);

        SessionManager manager;

        io::Controller controller;
        io::Config config;
        config.setInput(options_.input);
        config.setMsgPoolSize(128);
        config.setTimeout(0);
        config.setSnaplen(2048);

        auto& drv = config.addDriver("nfq");

        drv.setMode(Mode::Inline);
        drv.setPath(options_.driverPath);

        tcp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &manager);
        controller.init(config);

        controller.start();
        std::cout << "Starting reading '" << options_.input << "'..." << std::endl;

        RecvStatus status{RecvStatus::Ok};
        io::RawPacket* rawPacket{nullptr};
        do
        {
            status = controller.receivePacket(&rawPacket);
            if (rawPacket)
            {
                layers::Packet parsedPacket(rawPacket, false);
                auto status = tcpReassembly.reassemblePacket(parsedPacket);
                if (status == tcp::TcpReassembly::TcpMessageHandled)
                {
                    std::cout << "--handled--" << std::endl;

                    utils::printHex(std::cout, std::span{rawPacket->getRawData(),
                                                         (size_t)rawPacket->getRawDataLen()});
                    std::cout << "----" << std::endl;
                    auto p = parsedPacket.getLayerOfType<layers::PayloadLayer>(true);
                    if (p)
                    {
                        p->getData()[0] = 0xDE;

                        auto ip = parsedPacket.getLayerOfType<layers::IPv4Layer>(true);
                        ip->computeCalculateFields();

                        auto tcp = parsedPacket.getLayerOfType<layers::TcpLayer>(true);
                        tcp->computeCalculateFields();

                        controller.finalizePacket(rawPacket, Verdict::Replace);

                        std::cout << "--replaced--" << std::endl;

                        utils::printHex(std::cout, std::span{rawPacket->getRawData(),
                                                             (size_t)rawPacket->getRawDataLen()});
                        std::cout << "----" << std::endl;
                    }
                    else
                    {
                        controller.finalizePacket(rawPacket, Verdict::Pass);
                    }
                }
                /*
                else if (replaced)
                {
                    controller.finalizePacket(rawPacket, Verdict::Replace);
                }
                */
                else
                {
                    controller.finalizePacket(rawPacket, Verdict::Block);
                }
            }
        } while (status == RecvStatus::Ok);

        size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

        tcpReassembly.closeAllConnections();
        controller.stop();

        std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("spoofer", "Spoofer for TLS connections", Command);

} // namespace snet::spoofer
