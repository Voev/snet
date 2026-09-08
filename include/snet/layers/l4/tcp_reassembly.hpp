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

/**
 * @class TcpReassembly
 * A class containing the TCP reassembly logic. Please refer to the
 * documentation at the top of TcpReassembly.h for understanding how to use this
 * class
 */
class TcpReassembly
{
public:
    /**
     * An enum for providing reassembly status for each processed packet
     */
    enum ReassemblyStatus
    {
        Error_NoMemory,
        /**
         * The processed packet contains valid TCP payload, and its payload is
         * processed by `OnMessageReadyCallback` callback function. The packet
         * may be:
         * 1. An in-order TCP packet, meaning `packet_sequence ==
         * sequence_expected`. Note if there's any buffered out-of-order packet
         * waiting for this packet, their associated callbacks are called in
         * this `reassemblePacket` call.
         * 2. An out-of-order TCP packet which satisfy `packet_sequence <
         * sequence_expected && packet_sequence + packet_payload_length >
         * sequence_expected`. Note only the new data (the `[sequence_expected,
         *    packet_sequence + packet_payload_length]` part ) is processed by
         * `OnMessageReadyCallback` callback function.
         */
        TcpMessageHandled,
        /**
         * The processed packet is an out-of-order TCP packet, meaning
         * `packet_sequence > sequence_expected`. It's buffered so no
         * `OnMessageReadyCallback` callback function is called. The callback
         * function for this packet maybe called LATER, under different
         * circumstances:
         * 1. When an in-order packet which is right before this packet
         * arrives(case 1 and case 2 described in `TcpMessageHandled` section
         * above).
         * 2. When a FIN or RST packet arrives, which will clear the buffered
         * out-of-order packets of this side. If this packet contains "new
         * data", meaning `(packet_sequence <= sequence_expected) &&
         *    (packet_sequence + packet_payload_length > sequence_expected)`,
         * the new data is processed by `OnMessageReadyCallback` callback.
         */
        OutOfOrderTcpMessageBuffered,
        /**
         * The processed packet is a FIN or RST packet with no payload.
         * Buffered out-of-order packets will be cleared.
         * If they contain "new data", the new data is processed by
         * `OnMessageReadyCallback` callback.
         */
        FIN_RSTWithNoData,
        /**
         * The processed packet is not a SYN/SYNACK/FIN/RST packet and has no
         * payload. Normally it's just a bare ACK packet. It's ignored and no
         * callback function is called.
         */
        Ignore_PacketWithNoData,
        /**
         * The processed packet comes from a closed flow(an in-order FIN or RST
         * is seen). It's ignored and no callback function is called.
         */
        Ignore_PacketOfClosedFlow,
        /**
         * The processed packet is a restransmission packet with no new data,
         * meaning the `packet_sequence + packet_payload_length <
         * sequence_expected`. It's ignored and no callback function is called.
         */
        Ignore_Retransimission,
        /**
         * The processed packet is not an IP packet.
         * It's ignored and no callback function is called.
         */
        NonIpPacket,
        /**
         * The processed packet is not a TCP packet.
         * It's ignored and no callback function is called.
         */
        NonTcpPacket,
        /**
         * The processed packet does not belong to any known TCP connection.
         * It's ignored and no callback function is called.
         * Normally this will be happen.
         */
        Error_PacketDoesNotMatchFlow,
    };

    /**
     * The type for storing the connection information
     */
    typedef std::unordered_map<uint32_t, ConnectionInfo> ConnectionInfoList;

    /**
     * A c'tor for this class
     * @param[in] onMessageReadyCallback The callback to be invoked when new
     * data arrives
     * @param[in] userCookie A pointer to an object provided by the user. This
     * pointer will be returned when invoking the various callbacks. This
     * parameter is optional, default cookie is nullptr
     * @param[in] onConnectionStartCallback The callback to be invoked when a
     * new connection is identified. This parameter is optional
     * @param[in] onConnectionEndCallback The callback to be invoked when a new
     * connection is terminated (either by a FIN/RST packet or manually by the
     * user). This parameter is optional
     * @param[in] config Optional parameter for defining special configuration
     * parameters. If not set the default parameters will be set
     */
    explicit TcpReassembly(TcpReassemblyCallbacks callbacks, void* userCookie = nullptr,
                           TcpReassemblyConfig config = TcpReassemblyConfig());

    /**
     * The most important method of this class which gets a raw packet from the
     * user and processes it. If this packet opens a new connection, ends a
     * connection or contains new data on an existing connection, the relevant
     * callback will be invoked (TcpReassembly#OnTcpMessageReady,
     * TcpReassembly#OnTcpConnectionStart, TcpReassembly#OnTcpConnectionEnd)
     * @param[in] tcpRawData A reference to the raw packet to process
     * @return A enum of `TcpReassembly::ReassemblyStatus`, indicating status of
     * TCP reassembly
     */
    ReassemblyStatus reassemblePacket(Packet* packet);

    /**
     * Close a connection manually. If the connection doesn't exist or already
     * closed an error log is printed. This method will cause the
     * TcpReassembly#OnTcpConnectionEnd to be invoked with a reason of
     * TcpReassembly#TcpReassemblyConnectionClosedManually
     * @param[in] flowKey A 4-byte hash key representing the connection. Can be
     * taken from a ConnectionData instance
     */
    void closeConnection(uint32_t flowKey);

    /**
     * Close all open connections manually. This method will cause the
     * TcpReassembly#OnTcpConnectionEnd to be invoked for each connection with a
     * reason of TcpReassembly#TcpReassemblyConnectionClosedManually
     */
    void closeAllConnections();

    /**
     * Get a map of all connections managed by this TcpReassembly instance (both
     * connections that are open and those that are already closed)
     * @return A map of all connections managed. Notice this map is constant and
     * cannot be changed by the user
     */
    const ConnectionInfoList& getConnectionInformation() const
    {
        return m_ConnectionInfo;
    }

    /**
     * Check if a certain connection managed by this TcpReassembly instance is
     * currently opened or closed
     * @param[in] connection The connection to check
     * @return A positive number (> 0) if connection is opened, zero (0) if
     * connection is closed, and a negative number (< 0) if this connection
     * isn't managed by this TcpReassembly instance
     */
    int isConnectionOpen(const ConnectionInfo& connection) const;

    /**
     * Clean up the closed connections from the memory
     * @param[in] maxNumToClean The maximum number of items to be cleaned up per
     * one call. This parameter, when its value is not zero, overrides the value
     * that was set by the constructor.
     * @return The number of cleared items
     */
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

    typedef std::unordered_map<uint32_t, TcpReassemblyData> ConnectionList;
    typedef std::map<time_t, std::list<uint32_t>> CleanupList;

    using ContextTypes = std::tuple<TcpReassemblyData>;
    SessionManager<uint32_t, ContextTypes> sessionManager_;
    TcpReassemblyCallbacks callbacks_;
    TcpReassemblyConfig config_;
    void* m_UserCookie;
    ConnectionList m_ConnectionList;
    ConnectionInfoList m_ConnectionInfo;
    CleanupList m_CleanupList;
    time_t m_PurgeTimepoint;
    bool m_ProcessingOutOfOrder = false;
    std::unique_ptr<TcpFragmentPool> fragmentPool_;



    void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, bool cleanWholeFragList);

    void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey, bool isRst);

    void closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason);

    void insertIntoCleanupList(uint32_t flowKey);
};

} // namespace snet::layers
