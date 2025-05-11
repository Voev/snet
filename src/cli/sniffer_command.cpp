#include <iostream>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/error_code.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/layers/tcp_reassembly.hpp>

#include <snet/io.hpp>

#include <snet/crypto/asymm_key.hpp>

#include <snet/tls.hpp>

using namespace casket;
using namespace casket::log;
using namespace casket::opt;

namespace snet::sniffer
{

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
    std::string driverPath;
};

using SessionManager = std::unordered_map<uint32_t, std::shared_ptr<tls::Session>>;

class SnifferHandler final : public tls::IRecordHandler
{
public:
    SnifferHandler() = default;

    void handleRecord(const int8_t sideIndex, tls::Session* session, tls::Record*) override
    {
        if (sideIndex == 0 && session->handshake.type == tls::HandshakeType::ClientHello)
        {
            auto secrets = secretManager.getSecretNode(session->handshake.clientHello.random);
            if (secrets.has_value())
            {
                session->setSecrets(secrets.value());
            }
        }
    }

    tls::SecretNodeManager secretManager;
};

struct SnifferManager
{
    SnifferManager()
        : proc()
    {
        proc.addHandler<tls::RecordDecryptor>();
        proc.addHandler<SnifferHandler>();
        proc.addHandler<tls::RecordPrinter>();
    }

    tls::ServerInfo serverInfo;
    tls::RecordProcessor proc;
    tls::RecordPool recordPool;
    SessionManager sessions;
};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData, void* userCookie)
{
    auto mgr = static_cast<SnifferManager*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = mgr->sessions.find(tcpData.getConnectionData().flowKey);
        if (session == mgr->sessions.end())
        {
            auto result = mgr->sessions.emplace(
                std::make_pair(tcpData.getConnectionData().flowKey, std::make_shared<tls::Session>(mgr->recordPool)));
            if (result.second)
            {
                session = result.first;
                // session->second->setServerInfo(mgr->serverInfo);
            }
        }

        if (session->second)
        {
            try
            {
                mgr->proc.process(sideIndex, session->second.get(), const_cast<uint8_t*>(tcpData.getData()),
                                  tcpData.getDataLength());
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error processing payload with length " << tcpData.getDataLength() << ": " << e.what()
                          << '\n';
            }
        }
    }
}

void SniffPacketsFromFile(const std::string& ioDriver, const std::string& fileName, tcp::TcpReassembly& tcpReassembly)
{
    io::Controller controller;

    io::Config config;
    config.setInput(fileName);
    config.setMsgPoolSize(128);
    config.setTimeout(0);
    config.setSnaplen(2048);

    auto& drv = config.addDriver("my_driver");

    drv.setMode(Mode::ReadFile);
    drv.setPath(ioDriver);

    controller.init(config);

    controller.start();
    std::cout << "Starting reading '" << fileName << "'..." << std::endl;

    RecvStatus status{RecvStatus::Ok};
    io::RawPacket* rawPacket{nullptr};
    do
    {
        status = controller.receivePacket(&rawPacket);
        if (rawPacket)
        {
            tcpReassembly.reassemblePacket(rawPacket);
            controller.finalizePacket(rawPacket, Verdict::Pass);
        }
    } while (status == RecvStatus::Ok);

    size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

    tcpReassembly.closeAllConnections();
    controller.stop();

    std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;
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
            OptionBuilder("keylog", Value(&options_.keylog))
                .setDescription("Input key log file")
                .build()
        );
        parser_.add(
            OptionBuilder("key", Value(&options_.serverKeyPath))
                .setDescription("Server key path")
                .build()
        );
        parser_.add(
            OptionBuilder("driver", Value(&options_.driverPath))
                .setDescription("Driver path")
                .setRequired()
                .build()
        );
        parser_.add(
            OptionBuilder("input", Value(&options_.input))
                .setDescription("Input PCAP file")
                .setRequired()
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
            parser_.help(std::cout, "snet sniffer");
            return;
        }
        parser_.validate();

        LogManager::Instance().enable(Type::Console);

        SnifferManager manager;

        if (!options_.keylog.empty())
        {
            auto sniffer = manager.proc.getHandler<SnifferHandler>();
            sniffer->secretManager.parseKeyLogFile(options_.keylog);
        }

        if (!options_.serverKeyPath.empty())
        {
            auto serverKey = crypto::akey::fromStorage(KeyType::Private, options_.serverKeyPath);
            manager.serverInfo.setServerKey(serverKey);
        }

        tcp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &manager);
        SniffPacketsFromFile(options_.driverPath, options_.input, tcpReassembly);
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
