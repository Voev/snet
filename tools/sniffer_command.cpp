#include <iostream>
#include <snet/cmd/command_dispatcher.hpp>
#include <snet/opt/option_parser.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/log/log_manager.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>

#include <snet/tcp/tcp_reassembly.hpp>
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
};

using SessionManager = std::unordered_map<uint32_t, tls::Session>;

struct SnifferManager
{
    SnifferManager()
        : outputBuffer(16 * 1024)
    {}

    tls::SecretNodeManager secrets;
    SessionManager sessions;
    std::vector<uint8_t> outputBuffer;
};

void OnClientHello(tls::Session& session, void* userData)
{
    auto mgr = static_cast<SnifferManager*>(userData);
    auto secrets = mgr->secrets.getSecretNode(session.getClientRandom());
    if (secrets.has_value())
    {
        session.setSecrets(secrets.value());
    }
}

static tls::SessionCallbacks sessionCallbacks{ OnClientHello };

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex,
                                   const tcp::TcpStreamData& tcpData,
                                   void* userCookie)
{
    auto mgr = static_cast<SnifferManager*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = mgr->sessions.find(tcpData.getConnectionData().flowKey);
        if (session == mgr->sessions.end())
        {
            auto result = mgr->sessions.insert(std::make_pair(
                tcpData.getConnectionData().flowKey, tls::Session(sessionCallbacks, mgr)));
            if (result.second)
            {
                session = result.first;
            }
        }

        // check session!

        //utils::printHex({tcpData.getData(), tcpData.getDataLength()});

        try
        {
            size_t consumedBytes{0};
            auto data = std::span(tcpData.getData(), tcpData.getDataLength());
            while (data.size_bytes() > 0)
            {
                auto record = session->second.readRecord(sideIndex, data, mgr->outputBuffer, consumedBytes);

                session->second.processRecord(sideIndex, record);

                data = data.subspan(consumedBytes);
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
}

void SniffPacketsFromFile(const std::string& fileName,
                          tcp::TcpReassembly& tcpReassembly)
{
    auto reader = pcap::IFileReaderDevice::getReader(fileName);
    if (!reader->open())
    {
        std::cerr << "Cannot open pcap/pcapng file" << std::endl;
        return;
    }

    std::cout << "Starting reading '" << fileName << "'..." << std::endl;

    // run in a loop that reads one packet from the file in each iteration and
    // feeds it to the TCP reassembly instance
    layers::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket))
    {
        // вызываются коллбэки по обработке payload
        tcpReassembly.reassemblePacket(&rawPacket);
    }

    // extract number of connections before closing all of them
    size_t numOfConnectionsProcessed =
        tcpReassembly.getConnectionInformation().size();

    tcpReassembly.closeAllConnections();
    reader->close();

    std::cout << "Done! processed " << numOfConnectionsProcessed
              << " connections" << std::endl;
}

class Command final : public cmd::Command
{
public:
    Command()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("input, i", opt::Value(&options_.input), "Input PCAP file");
        parser_.add("keylog, k", opt::Value(&options_.keylog),
                    "Input key log file");
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
            manager.secrets.parseKeyLogFile(options_.keylog);

        tcp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback,
                                         &manager);
        SniffPacketsFromFile(options_.input, tcpReassembly);
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
