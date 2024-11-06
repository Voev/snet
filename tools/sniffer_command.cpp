#include <iostream>
#include <snet/cmd/command_dispatcher.hpp>
#include <snet/opt/option_parser.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/log/log_manager.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>

#include <snet/tcp/tcp_reassembly.hpp>

using namespace snet::log;
using namespace snet::pcap;

namespace snet::sniffer
{

struct Options
{
    std::string input;
};

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData, void* userCookie)
{
    (void)sideIndex;
    (void)tcpData;
    (void)userCookie;

    if (tcpData.getMissingByteCount() == 0)
    {
        // начинаем обрабатывать record-ы
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
        tcpReassembly.reassemblePacket(&rawPacket); // вызываются коллбэки по обработке payload
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

        tcp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback);
        SniffPacketsFromFile(options_.input, tcpReassembly);
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
