#pragma once
#include <cstdint>

#include <snet/session.hpp>
#include <snet/tls.hpp>
#include <snet/tcp/tcp_types.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>

#include <snet/config_parser/config_parser.hpp>
#include "pcap_test.hpp"

using SessionContexts = std::tuple<snet::tcp::TcpConnection, snet::tls::TlsDecryptContext>;
using SessionManager = snet::session::SessionManager<uint32_t, SessionContexts>;
using DecryptConsumer = snet::tls::TlsDecryptStreamConsumer<SessionManager>;

class DecryptByKeylog final : public PcapTestImpl
{
public:
    explicit DecryptByKeylog(const ConfigParser::Section& section);

    void execute() override;

private:
    snet::tcp::RxRingPool rxPool_;
    snet::tls::RecordPool recordPool_;
    snet::tls::SecretNodeManager secretManager_;
    SessionManager sessionManager_;
    std::unique_ptr<DecryptConsumer> consumer_;
    size_t expectedDecryptedRecordCount_{1};
};