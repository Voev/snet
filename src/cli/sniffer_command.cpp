#include <iostream>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/string.hpp>
#include <casket/utils/error_code.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/layers/tcp_reassembly.hpp>

#include <snet/io.hpp>

#include <snet/crypto/asymm_key.hpp>

#include <snet/tls.hpp>

using namespace casket;
using namespace casket::opt;

namespace snet::sniffer
{

static inline Level ParseLogLevel(std::string_view str)
{
    if (::iequals(str, "alert"))
    {
        return Level::Alert;
    }
    else if (::iequals(str, "crit"))
    {
        return Level::Critical;
    }
    else if (::iequals(str, "error"))
    {
        return Level::Error;
    }
    else if (::iequals(str, "warn"))
    {
        return Level::Warning;
    }
    else if (::iequals(str, "notice"))
    {
        return Level::Notice;
    }
    else if (::iequals(str, "info"))
    {
        return Level::Info;
    }
    else if (::iequals(str, "debug"))
    {
        return Level::Debug;
    }

    return Level::Emergency;
}

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
    std::string driverPath;
    std::string logLevel;
};

using SessionManager = std::unordered_map<uint32_t, std::shared_ptr<tls::Session>>;

struct SnifferManager
{
    SnifferManager()
        : recordPool(1024)
        , proc(std::make_shared<tls::RecordHandlers>())
    {
        proc->push_back(std::make_shared<tls::SnifferHandler>(secretManager));
        proc->push_back(std::make_shared<tls::RecordPrinter>());
    }

    tls::RecordPool recordPool;
    tls::RecordProcessor proc;
    tls::SecretNodeManager secretManager;
    crypto::KeyPtr serverKey;
    SessionManager sessions;
    io::Controller controller;
};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const layers::TcpStreamData& tcpData, void* userCookie)
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
                session->second->setProcessor(mgr->proc);
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
            OptionBuilder("log-level", Value(&options_.logLevel))
                .setDescription("Log level")
                .setDefaultValue("warn")
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
        LogManager::Instance().setLevel(ParseLogLevel(options_.logLevel));

        SnifferManager manager;

        io::DriverConfig drvConfig;
        drvConfig.setPath(options_.driverPath);

        auto driver = manager.controller.load(drvConfig);

        io::Config config;
        config.setInput(options_.input);
        config.setMsgPoolSize(128);
        config.setTimeout(0);
        config.setSnaplen(2048);
        config.setMode(Mode::ReadFile);

        driver->configure(config);

        if (!options_.keylog.empty())
        {
            manager.secretManager.parseKeyLogFile(options_.keylog);
        }

        if (!options_.serverKeyPath.empty())
        {
            manager.serverKey = crypto::AsymmKey::fromStorage(KeyType::Private, options_.serverKeyPath);
        }

        driver->start();
        std::cout << "Start processing: '" << options_.input << "'..." << std::endl;

        layers::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &manager);
        RecvStatus status{RecvStatus::Ok};
        layers::Packet* packet{nullptr};
        do
        {
            status = driver->receivePacket(&packet);
            if (packet)
            {
                tcpReassembly.reassemblePacket(packet);
                driver->finalizePacket(packet, Verdict::Pass);
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

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
