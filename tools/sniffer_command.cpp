#include <iostream>
#include <snet/cmd/command_dispatcher.hpp>
#include <snet/opt/option_parser.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/log/log_manager.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>

using namespace snet::log;
using namespace snet::pcap;

namespace snet::sniffer
{

struct Options
{
    std::string input;
};

void SniffPackets(PcapFileReaderDevice& reader, std::ostream& out,
                  int packetCount)
{
    // read packets from the file until end-of-file or until reached user
    // requested packet count
    int packetCountSoFar = 0;
    RawPacket rawPacket;
    while (reader.getNextPacket(rawPacket) && packetCountSoFar != packetCount)
    {
        packetCountSoFar++;
        out << rawPacket.getRawDataLen() << std::endl;
    }
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

        PcapFileReaderDevice dev(options_.input);
        dev.open();
        SniffPackets(dev, std::cout, 10);
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
