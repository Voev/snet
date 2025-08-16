#pragma once
#include <string>
#include <vector>

#include <snet/tls.hpp>
#include <snet/layers/tcp_reassembly.hpp>

#include <snet/config_parser/config_parser.hpp>
#include "pcap_test.hpp"

class DecryptByKeylog final : public PcapTestImpl
{
public:
    explicit DecryptByKeylog(const ConfigParser::Section& section);

    void execute() override;

    friend void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const snet::layers::TcpStreamData& tcpData,
                                              void* userCookie);

private:
    snet::tls::RecordPool recordPool_;
    snet::tls::RecordProcessor processor_;
    snet::tls::SecretNodeManager secretManager_;
    snet::layers::TcpReassembly reassembler_;
    std::unordered_map<uint32_t, std::shared_ptr<snet::tls::Session>> sessions_;
    size_t decryptedRecordCount_{1};
};