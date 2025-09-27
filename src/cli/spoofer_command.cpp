#include <iostream>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
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
using namespace casket::opt;

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

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const layers::TcpStreamData& tcpData,
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
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder("input", Value(&options_.input))
                .setDescription("Input PCAP file")
                .build()
        );
        parser_.add(
            OptionBuilder("driver", Value(&options_.driverPath))
                .setDescription("Driver path")
                .build()
        );
        // clang-format on
    }

    ~Command() = default;

    void execute(const std::vector<std::string_view>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout, "snet spoofer");
            return;
        }
        parser_.validate();

        LogManager::Instance().enable(Type::Console);

        SessionManager manager;

        io::Config config;
        config.setInput(options_.input);
        config.setMsgPoolSize(128);
        config.setTimeout(0);
        config.setSnaplen(2048);
        config.setMode(Mode::Inline);
        
        io::DriverConfig drv;
        drv.setPath(options_.driverPath);

        io::Controller controller;
        auto driver = controller.load(drv);

        layers::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &manager);
        driver->configure(config);

        driver->start();
        std::cout << "Starting reading '" << options_.input << "'..." << std::endl;

        RecvStatus status{RecvStatus::Ok};
        layers::Packet* packet{nullptr};
        do
        {
            status = driver->receivePacket(&packet);
            if (packet)
            {
                auto status = tcpReassembly.reassemblePacket(packet);
                if (status == layers::TcpReassembly::TcpMessageHandled)
                {
                    std::cout << "--handled--" << std::endl;

                    utils::printHex(std::cout, nonstd::span{packet->getData(),
                                                         (size_t)packet->getDataLen()});
                    std::cout << "----" << std::endl;
                    auto p = packet->getLayerOfType<layers::PayloadLayer>(true);
                    if (p)
                    {
                        p->getData()[0] = 0xDE;

                        auto ip = packet->getLayerOfType<layers::IPv4Layer>(true);
                        ip->computeCalculateFields();

                        auto tcp = packet->getLayerOfType<layers::TcpLayer>(true);
                        tcp->computeCalculateFields();

                        driver->finalizePacket(packet, Verdict::Replace);

                        std::cout << "--replaced--" << std::endl;

                        utils::printHex(std::cout, nonstd::span{packet->getData(),
                                                             (size_t)packet->getDataLen()});
                        std::cout << "----" << std::endl;
                    }
                    else
                    {
                        driver->finalizePacket(packet, Verdict::Pass);
                    }
                }
                /*
                else if (replaced)
                {
                    driver->finalizePacket(rawPacket, Verdict::Replace);
                }
                */
                else
                {
                    driver->finalizePacket(packet, Verdict::Block);
                }
            }
        } while (status == RecvStatus::Ok);

        size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

        tcpReassembly.closeAllConnections();
        driver->stop();

        std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("spoofer", "Spoofer for TLS connections", Command);

} // namespace snet::spoofer
