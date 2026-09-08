#pragma once

#include <functional>

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_types.hpp>
#include <snet/layers/l4/tcp_stream.hpp>
#include <snet/layers/l4/tcp_fragment_pool.hpp>
#include <snet/utils/pointer_vector.hpp>
#include <unordered_map>
#include <chrono>
#include <map>
#include <list>
#include <time.h>

#include <snet/layers/session_manager.hpp>

namespace snet::layers
{

class TcpReassembly;

struct TcpReassemblyCallbacks
{
    using OnTcpMessageReady = std::function<void(int8_t side, const TcpStreamData& data, void* userData)>;
    using OnTcpConnectionStart = std::function<void(const ConnectionInfo& info, void* userData)>;
    using OnTcpConnectionClose =
        std::function<void(const ConnectionInfo& info, ConnectionEndReason reason, void* userData)>;

    OnTcpMessageReady onMessageReady;
    OnTcpConnectionStart onConnectionStart;
    OnTcpConnectionClose onConnectionClose;
};

struct TcpReassemblyConfig
{
    TcpFragmentPoolConfig poolConfig;
    uint32_t closeDelaySec{5};
    uint32_t maxCleanup{30};
    uint32_t maxOutOfOrder{0};
    bool removeConnInfo{true};
    bool enableBaseBufferClear{true};
};

class TcpReassembly
{
public:
    enum ReassemblyStatus
    {
        Error_NoMemory,
        TcpMessageHandled,
        OutOfOrderTcpMessageBuffered,
        FIN_RSTWithNoData,
        Ignore_PacketWithNoData,
        Ignore_PacketOfClosedFlow,
        Ignore_Retransimission,
        NonIpPacket,
        NonTcpPacket,
        Error_PacketDoesNotMatchFlow,
    };

    explicit TcpReassembly(TcpReassemblyCallbacks callbacks, void* userCookie = nullptr,
                           TcpReassemblyConfig config = TcpReassemblyConfig());

    ReassemblyStatus reassemblePacket(Packet* packet);

    void closeConnection(uint32_t flowKey);

    void closeAllConnections();

    int isConnectionOpen(const ConnectionInfo& connection) const;

    uint32_t purgeClosedConnections(uint32_t maxNumToClean = 0);

private:
    struct TcpOneSideData
    {
        IPAddress srcIP;
        uint16_t srcPort;
        uint32_t sequence;
        std::map<uint32_t, TcpFragment*> tcpFragments;
        bool gotFinOrRst;

        TcpOneSideData()
            : srcPort(0)
            , sequence(0)
            , gotFinOrRst(false)
        {
        }

        TcpOneSideData(const TcpOneSideData&) = delete;
        TcpOneSideData& operator=(const TcpOneSideData&) = delete;

        TcpOneSideData(TcpOneSideData&& other) noexcept
            : srcIP(other.srcIP)
            , srcPort(other.srcPort)
            , sequence(other.sequence)
            , tcpFragments(std::move(other.tcpFragments))
            , gotFinOrRst(other.gotFinOrRst)
        {
        }

        TcpOneSideData& operator=(TcpOneSideData&& other) noexcept
        {
            if (this != &other)
            {
                tcpFragments.clear();
                srcIP = other.srcIP;
                srcPort = other.srcPort;
                sequence = other.sequence;
                tcpFragments = std::move(other.tcpFragments);
                gotFinOrRst = other.gotFinOrRst;
            }
            return *this;
        }
    };

    struct TcpReassemblyData
    {
        static constexpr size_t MAX_INSTANCES = 1;
        bool closed;
        int8_t numOfSides;
        int8_t prevSide;
        TcpOneSideData twoSides[2];
        ConnectionInfo connData;

        TcpReassemblyData()
            : closed(false)
            , numOfSides(0)
            , prevSide(-1)
        {
        }
    };

    class OutOfOrderProcessingGuard
    {
    private:
        bool& m_Flag;

    public:
        explicit OutOfOrderProcessingGuard(bool& flag)
            : m_Flag(flag)
        {
            m_Flag = true;
        }

        ~OutOfOrderProcessingGuard()
        {
            m_Flag = false;
        }

        // Disable copy and move operations
        OutOfOrderProcessingGuard(const OutOfOrderProcessingGuard&) = delete;
        OutOfOrderProcessingGuard& operator=(const OutOfOrderProcessingGuard&) = delete;
    };

    using ContextTypes = std::tuple<TcpReassemblyData>;
    SessionManager<uint32_t, ContextTypes> sessionManager_;
    TcpReassemblyCallbacks callbacks_;
    TcpReassemblyConfig config_;
    void* m_UserCookie;
    bool m_ProcessingOutOfOrder = false;
    std::unique_ptr<TcpFragmentPool> fragmentPool_;

    void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, bool cleanWholeFragList);

    void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey, bool isRst);

    void closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason);
};

} // namespace snet::layers
