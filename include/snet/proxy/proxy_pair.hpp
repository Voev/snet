#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/session.hpp>

#include "proxy_types.hpp"

namespace snet::proxy
{

struct ProxyPair
{
    uint32_t downstreamKey{0};
    uint32_t upstreamKey{0};

    snet::layers::IPAddress clientIP{};
    uint16_t                clientPort{0};
    snet::layers::IPAddress serverIP{};
    uint16_t                serverPort{0};

    PairPhase phase{PairPhase::Waiting};

    uint64_t bytesToServer{0};
    uint64_t bytesToClient{0};
    uint64_t clientTlsRecords{0};
    uint64_t serverTlsRecords{0};

    std::string        clientSni;
    InspectionDecision decision{InspectionDecision::Bypass};

    std::vector<uint8_t> bufferedClientHello;

    snet::tls::RecordPool pool{64};

    std::unique_ptr<snet::tls::Session> clientTls;
    std::unique_ptr<snet::tls::Session> serverTls;

    bool downstreamEstablished{false};
    bool upstreamEstablished{false};
    bool downstreamClosed{false};
    bool upstreamClosed{false};
};

using ProxyPairPtr = std::shared_ptr<ProxyPair>;

} // namespace snet::proxy