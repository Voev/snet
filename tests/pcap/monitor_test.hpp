#pragma once
#include <cstdint>

#include <snet/session.hpp>
#include <snet/tls.hpp>
#include <snet/tcp/tcp_types.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>
#include <snet/tcp/tcp_listener_handler.hpp>

#include <snet/tls/monitor_tls_stream_consumer.hpp>

#include <snet/config_parser/config_parser.hpp>
#include "pcap_test.hpp"

using SessionContexts = std::tuple<snet::tcp::TcpConnection, snet::tls::TlsDecryptContext>;
using SessionManager = snet::session::SessionManager<uint32_t, SessionContexts>;
using MonitorConsumer = snet::tls::MonitorTlsStreamConsumer<SessionManager>;

class MonitorTest final : public PcapTestImpl
{
public:
    explicit MonitorTest(const ConfigParser::Section& section);

    void execute() override;

private:
    snet::tcp::RxRingPool rxPool_;
    snet::tls::RecordPool recordPool_;
    SessionManager sessionManager_;
    std::unique_ptr<MonitorConsumer> consumer_;
    size_t expectedProcessedRecords_;
};