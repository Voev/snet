#include <iostream>
#include <snet/cli/command_dispatcher.hpp>
#include <snet/opt/option_parser.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/log/log_manager.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>

#include <snet/layers/tcp_reassembly.hpp>
#include <snet/utils/hexlify.hpp>
#include <snet/tls.hpp>

using namespace snet::log;
using namespace snet::pcap;

namespace snet::sniffer
{

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
};

using SessionManager = std::unordered_map<uint32_t, std::unique_ptr<tls::Session>>;

struct SnifferManager
{
    SnifferManager()
    {
    }

    tls::SecretNodeManager secrets;
    tls::ServerInfo serverInfo;
    SessionManager sessions;
};

void OnAlert(const int8_t, const tls::Alert& alert)
{
    std::cout << alert.toString() << std::endl;
}

void OnAppData(const int8_t, std::span<const uint8_t> appData)
{
    utils::printHex(appData);
}

void OnClientHello(tls::Session& session, void* userData)
{
    auto mgr = static_cast<SnifferManager*>(userData);

    auto secrets = mgr->secrets.getSecretNode(session.getClientRandom());
    if (secrets.has_value())
    {
        session.setSecrets(secrets.value());
    }
}

void OnRecord(const int8_t sideIndex, const tls::Record& record)
{
    std::cout << (sideIndex == 0 ? "C -> S" : "S -> C");
    std::cout << ", " << tls::toString(record.type()) << " [" << record.totalLength() << "]" << std::endl;
}

void OnHandshake(const int8_t, const tls::HandshakeType type,
                 std::span<const uint8_t> message)
{
    std::cout << tls::toString(type) << "[" << message.size() << "]" << std::endl;
    utils::printHex(message);
}

static tls::SessionCallbacks sessionCallbacks{OnClientHello, OnRecord, OnHandshake, OnAlert,
                                              OnAppData};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData,
                                   void* userCookie)
{
    auto mgr = static_cast<SnifferManager*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = mgr->sessions.find(tcpData.getConnectionData().flowKey);
        if (session == mgr->sessions.end())
        {
            auto result = mgr->sessions.emplace(std::make_pair(tcpData.getConnectionData().flowKey,
                                                               std::make_unique<tls::Session>()));
            if (result.second)
            {
                session = result.first;
                session->second->setCallbacks(sessionCallbacks, mgr);
                session->second->setServerInfo(mgr->serverInfo);
            }
        }

        if (session->second)
            session->second->processBytes(sideIndex, {tcpData.getData(), tcpData.getDataLength()});
        
    }
}

void SniffPacketsFromFile(const std::string& fileName, tcp::TcpReassembly& tcpReassembly)
{
    auto reader = pcap::IFileReaderDevice::getReader(fileName);
    if (!reader->open())
    {
        std::cerr << "Cannot open pcap/pcapng file" << std::endl;
        return;
    }

    std::cout << "Starting reading '" << fileName << "'..." << std::endl;

    layers::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket))
    {
        tcpReassembly.reassemblePacket(&rawPacket);
    }

    size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

    tcpReassembly.closeAllConnections();
    reader->close();

    std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;
}

class Command final : public cmd::Command
{
public:
    Command()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("input, i", opt::Value(&options_.input), "Input PCAP file");
        parser_.add("keylog, l", opt::Value(&options_.keylog), "Input key log file");
        parser_.add("key, k", opt::Value(&options_.serverKeyPath), "Server key path");
    }

    ~Command() = default;

    void execute(const std::vector<std::string>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout);
            return;
        }

        LogManager::Instance().enable(Type::Console);

        SnifferManager manager;

        if (!options_.keylog.empty())
        {
            manager.secrets.parseKeyLogFile(options_.keylog);
        }

        if (!options_.serverKeyPath.empty())
        {
            auto serverKey = tls::LoadPrivateKey(options_.serverKeyPath);
            manager.serverInfo.setServerKey(serverKey);
        }

        tcp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &manager);
        SniffPacketsFromFile(options_.input, tcpReassembly);
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
