#include <iostream>

#include <casket/thread/pool.hpp>
#include <casket/log/log_manager.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/error_code.hpp>

#include <casket/lock_free/queue.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/layers/tcp_reassembly.hpp>
#include <snet/layers/ip_layer.hpp>
#include <snet/layers/tcp_layer.hpp>

#include <snet/io.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/crypto/asymm_key.hpp>

#include <snet/tls.hpp>

using namespace casket;
using namespace casket::log;
using namespace casket::opt;
using namespace casket::thread;

using namespace snet::layers;

namespace snet::sniffer
{

struct Options
{
    std::string input;
    std::string keylog;
    std::string serverKeyPath;
    std::string driverPath;
};

struct SnifferData
{
    SnifferData()
    {
        proc.addReader<tls::RecordReader>();
        proc.addHandler<tls::RecordDecryptor>();
        proc.addHandler<tls::RecordPrinter>();
    }

    tls::RecordProcessor proc;
    std::unordered_map<uint32_t, std::shared_ptr<tls::Session>> sessions;
};

void OnConnectionStart(const tcp::ConnectionData& conn, void*)
{
    log::debug("[{}] {}:{} -> {}:{}", std::this_thread::get_id(), conn.srcIP.toString(), conn.srcPort,
               conn.dstIP.toString(), conn.dstPort);
}

void OnConnectionEnd(const tcp::ConnectionData& conn, tcp::TcpReassembly::ConnectionEndReason, void*)
{
    log::debug("[{}] {}:{} -> {}:{}", std::this_thread::get_id(), conn.srcIP.toString(), conn.srcPort,
               conn.dstIP.toString(), conn.dstPort);
}

void TcpReassemblerCallback(const int8_t sideIndex, const tcp::TcpStreamData& tcpData, void* userCookie)
{
    auto mgr = static_cast<SnifferData*>(userCookie);

    if (tcpData.getMissingByteCount() == 0)
    {
        auto session = mgr->sessions.find(tcpData.getConnectionData().flowKey);
        if (session == mgr->sessions.end())
        {
            auto result = mgr->sessions.emplace(
                std::make_pair(tcpData.getConnectionData().flowKey, std::make_shared<tls::Session>()));
            if (result.second)
            {
                session = result.first;
            }
        }

        if (session->second)
        {
            auto payload = std::span(tcpData.getData(), tcpData.getDataLength());
            try
            {
                mgr->proc.process(sideIndex, session->second.get(), payload);
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error processing payload with length " << payload.size_bytes() << ": " << e.what()
                          << '\n';
            }
        }
    }
}

struct SnifferWorker
{
    SnifferWorker(lock_free::Queue<io::RawPacket*>& txQueue)
        : reassembler_(TcpReassemblerCallback, &data_, OnConnectionStart, OnConnectionEnd)
        , rxQueue_()
        , txQueue_(txQueue)
        , stopped_(false)
    {
    }

    void push(io::RawPacket* rawPacket)
    {
        rxQueue_.push(rawPacket);
    }

    void start()
    {
        while (!stopped_)
        {
            auto packet = rxQueue_.pop();
            if (packet.has_value())
            {
                reassembler_.reassemblePacket(packet.value());
                txQueue_.push(packet.value());
            }
        }
    }

    void stop()
    {
        stopped_ = true;
    }

    tcp::TcpReassembly reassembler_;
    lock_free::Queue<io::RawPacket*> rxQueue_;
    lock_free::Queue<io::RawPacket*>& txQueue_;
    SnifferData data_;
    std::atomic_bool stopped_;
};

struct SnifferThread
{
    SnifferThread(lock_free::Queue<io::RawPacket*>& txQueue)
        : worker_(txQueue)
        , thread_([this]() { worker_.start(); })
    {
    }

    ~SnifferThread()
    {
        stop();
    }

    void stop()
    {
        worker_.stop();

        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    SnifferWorker worker_;
    std::thread thread_;
};

class Sniffer
{
public:
    Sniffer(const io::Config& config, size_t threadsCount)
    {
        controller_.init(config);

        for (size_t i = 0; i < threadsCount; ++i)
        {
            workers_.emplace_back(std::make_unique<SnifferThread>(output_queue_));
        }
    }

    ~Sniffer()
    {
        for (size_t i = 0; i < workers_.size(); ++i)
        {
            workers_[i]->stop();
        }

        controller_.final();
    }

    void run()
    {
        RecvStatus status{RecvStatus::Ok};

        controller_.start();

        while (controller_.getState() != io::Controller::State::Stopped)
        {
            io::RawPacket* rawPacket{nullptr};
            status = controller_.receivePacket(&rawPacket);

            if (status == RecvStatus::Ok && rawPacket)
            {
                layers::Packet packet(rawPacket);
                auto rssHash = calcRssHash(packet);
                size_t workerId = rssHash % workers_.size();
                workers_[workerId]->worker_.push(rawPacket);
            }

            auto txPacket = output_queue_.pop();
            while (txPacket.has_value())
            {
                controller_.finalizePacket(txPacket.value(), Verdict::Pass);
                txPacket = output_queue_.pop();
            }
        }
    }

    static uint32_t calcRssHash(const Packet& packet)
    {
        auto ip = packet.getLayerOfType<IPLayer>();
        auto tcp = packet.getLayerOfType<TcpLayer>();

        ip::IPAddress src_ip = ip->getSrcIPAddress();
        ip::IPAddress dst_ip = ip->getDstIPAddress();
        auto src_port = tcp->getSrcPort();
        auto dst_port = tcp->getDstPort();

        bool swap = src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port);

        uint32_t hash_ip1 = swap ? std::hash<ip::IPAddress>{}(dst_ip) : std::hash<ip::IPAddress>{}(src_ip);
        uint32_t hash_ip2 = swap ? std::hash<ip::IPAddress>{}(src_ip) : std::hash<ip::IPAddress>{}(dst_ip);
        uint16_t hash_port1 = swap ? dst_port : src_port;
        uint16_t hash_port2 = swap ? src_port : dst_port;

        uint32_t hash = hash_ip1;
        hash ^= hash_ip2;
        hash ^= (hash_port1 << 16 | hash_port2);

        hash = (hash >> 16) ^ (hash << 16);
        hash ^= (hash >> 8);

        return hash;
    }

private:
    io::Controller controller_;
    std::vector<std::unique_ptr<SnifferThread>> workers_;
    lock_free::Queue<io::RawPacket*> output_queue_;
};

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

        io::Config config;
        config.setInput(options_.input);
        config.setMsgPoolSize(128);
        config.setTimeout(0);
        config.setSnaplen(2048);

        auto& drv = config.addDriver("my");

        drv.setMode(Mode::ReadFile);
        drv.setPath(options_.driverPath);

        Sniffer sniffer(config, 1);
        sniffer.run();
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("sniffer", "Sniffer for TLS connections", Command);

} // namespace snet::sniffer
