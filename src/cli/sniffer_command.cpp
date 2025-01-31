#include <iostream>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_parser.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/error_code.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>
#include <snet/layers/tcp_reassembly.hpp>

#include <snet/tls.hpp>

using namespace casket;
using namespace casket::log;
using namespace snet::pcap;

namespace snet::sniffer
{

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
};

using SessionManager = std::unordered_map<uint32_t, std::shared_ptr<tls::Session>>;

class RecordPrinter final : public tls::IRecordHandler
{
public:
    RecordPrinter() = default;

    ~RecordPrinter() = default;

    void handleRecord(const std::int8_t sideIndex, const tls::Record& record) override
    {
        tls::HandshakeType ht{tls::HandshakeType::None};
        if (record.type() == tls::RecordType::Handshake)
        {
            ht = static_cast<tls::HandshakeType>(record.data()[0]);
        }
        std::cout << (sideIndex == 0 ? "C -> S" : "C <- S");
        std::cout << ", " << record.version().toString() << ", " << tls::toString(record.type())
                  << " [" << record.totalLength() << "] "
                  << (ht != tls::HandshakeType::None ? tls::toString(ht) : "") << std::endl;
        utils::printHex(record.data());
    }
};

class SnifferHandler final : public tls::IRecordHandler
{
public:

    SnifferHandler() = default;

    void handleRecord(const std::int8_t sideIndex, const tls::Record& record) override
    {
        if (sideIndex == 0 && record.type() == tls::RecordType::Handshake)
        {
            auto ht = static_cast<tls::HandshakeType>(record.data()[0]);
            if (ht == tls::HandshakeType::ClientHello)
            {
                auto secrets = secretManager.getSecretNode(session->getClientRandom());
                if (secrets.has_value())
                {
                    session->setSecrets(secrets.value());
                }
            }
        }
    }

    tls::SecretNodeManager secretManager;
    std::shared_ptr<tls::Session> session;
};

struct SnifferManager
{
    SnifferManager()
    {
        proc.addReader<tls::RecordReader>();
        proc.addHandler<tls::RecordDecryptor>();
        proc.addHandler<SnifferHandler>();
        proc.addHandler<RecordPrinter>();
    }

    tls::ServerInfo serverInfo;
    tls::RecordProcessor proc;
    SessionManager sessions;
};

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
                                                               std::make_shared<tls::Session>()));
            if (result.second)
            {
                session = result.first;
                // session->second->setServerInfo(mgr->serverInfo);
            }
        }

        if (session->second)
        {
            auto rr = mgr->proc.getReader<tls::RecordReader>();
            if (rr)
                rr->setSession(session->second);

            auto rd = mgr->proc.getHandler<tls::RecordDecryptor>();
            if (rd)
                rd->setSession(session->second);

            auto sh = mgr->proc.getHandler<SnifferHandler>();
            if (sh)
                sh->session = session->second;

            auto payload = std::span(tcpData.getData(), tcpData.getDataLength());
            try
            {
                mgr->proc.process(sideIndex, payload);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error processing payload with length " << payload.size_bytes() << ": "
                          << e.what() << '\n';
            }
        }
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

    void execute(const std::vector<std::string_view>& args) override
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
            auto sniffer = manager.proc.getHandler<SnifferHandler>();
            sniffer->secretManager.parseKeyLogFile(options_.keylog);
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
