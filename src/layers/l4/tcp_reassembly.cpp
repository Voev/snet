#include <cstring>
#include <snet/layers/l4/tcp_reassembly.hpp>
#include <snet/layers/checksums.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/log/log.hpp>

using namespace casket;

#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)

namespace snet::layers
{

TcpReassembly::TcpReassembly(TcpReassemblyCallbacks callbacks, void* userCookie, TcpReassemblyConfig config)
    : callbacks_(std::move(callbacks))
    , config_(std::move(config))
    , fragmentPool_(std::make_unique<TcpFragmentPool>(config_.poolConfig))
{
    m_UserCookie = userCookie;
}

TcpReassembly::ReassemblyStatus TcpReassembly::reassemblePacket(Packet* packet)
{
    // calculate packet's source and dest IP address
    IPAddress srcIP, dstIP;

    auto ipHeader = packet->getHeader<IPv4Header>(IPv4);
    if (ipHeader.isValid())
    {
        srcIP = IPAddress(ipHeader.srcAddr());
        dstIP = IPAddress(ipHeader.dstAddr());
    }
    else
        return NonIpPacket;

    // Ignore non-TCP packets
    const auto* layer = packet->findLayer(TCP);
    if (!layer)
    {
        return NonTcpPacket;
    }
    auto tcpHeader = packet->getHeader<TCPHeader>(*layer);

    ReassemblyStatus status = TcpMessageHandled;

    // set the TCP payload size
    size_t tcpPayloadSize = packet->getPayloadSize(layer);

    // calculate if this packet has FIN or RST flags
    bool isFin = tcpHeader.isFIN();
    bool isRst = tcpHeader.isRST();
    bool isFinOrRst = isFin || isRst;

    // ignore ACK packets or TCP packets with no payload (except for SYN, FIN or
    // RST packets which we'll later need)
    if (tcpPayloadSize == 0 && !tcpHeader.isSYN() && !isFinOrRst)
    {
        return Ignore_PacketWithNoData;
    }

    TcpReassemblyData* tcpReassemblyData = nullptr;

    // calculate flow key for this packet
    uint32_t flowKey =
        layers::hash5Tuple(srcIP, dstIP, tcpHeader.srcPort(), tcpHeader.dstPort(), ipHeader.protocol(), false);

    // time stamp for this packet
    auto currTime = packet->getTimestamp().toTimePoint();

    // find the connection using SessionManager
    auto* session = sessionManager_.find(flowKey);
    
    if (!session)
    {
        // Create new TcpReassemblyData context
        auto* newData = sessionManager_.allocateContext<TcpReassemblyData>();
        if (!newData)
        {
            CSK_LOG_ERROR("Cannot allocate TcpReassemblyData");
            return Error_NoMemory;
        }

        // Create session with context
        session = sessionManager_.getOrCreate(flowKey, newData);
        if (!session)
        {
            sessionManager_.deallocateContext(newData);
            CSK_LOG_ERROR("Cannot create session");
            return Error_NoMemory;
        }

        tcpReassemblyData = newData;
        tcpReassemblyData->connData.tuple = ConnectionTuple({srcIP, tcpHeader.srcPort()}, {dstIP, tcpHeader.dstPort()});
        tcpReassemblyData->connData.start_time = currTime;

        // fire connection start callback
        if (callbacks_.onConnectionStart != nullptr)
            callbacks_.onConnectionStart(tcpReassemblyData->connData, m_UserCookie);
    }
    else
    {
        // Get TcpReassemblyData from session
        tcpReassemblyData = sessionManager_.getContext<TcpReassemblyData>(session);
        if (!tcpReassemblyData)
        {
            CSK_LOG_ERROR("Session exists but TcpReassemblyData is null");
            return Error_NoMemory;
        }

        // if this packet belongs to a connection that was already closed
        if (tcpReassemblyData->closed)
        {
            CSK_LOG_DEBUG("Ignoring packet of already closed flow [0x%lx]", flowKey);
            return Ignore_PacketOfClosedFlow;
        }

        if (currTime > tcpReassemblyData->connData.end_time)
        {
            tcpReassemblyData->connData.end_time = currTime;
        }
    }

    int8_t sideIndex = -1;
    bool first = false;

    // calculate packet's source port
    uint16_t srcPort = tcpHeader.srcPort();

    // if this is a new connection and it's the first packet we see on that connection
    if (tcpReassemblyData->numOfSides == 0)
    {
        CSK_LOG_DEBUG("Setting side for new connection");

        // open the first side of the connection, side index is 0
        sideIndex = 0;
        tcpReassemblyData->twoSides[sideIndex].srcIP = srcIP;
        tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;
        tcpReassemblyData->numOfSides++;
        first = true;
    }
    // if there is already one side in this connection (which will be at side index 0)
    else if (tcpReassemblyData->numOfSides == 1)
    {
        // check if packet belongs to that side
        if (tcpReassemblyData->twoSides[0].srcPort == srcPort && tcpReassemblyData->twoSides[0].srcIP == srcIP)
        {
            sideIndex = 0;
        }
        else
        {
            // this means packet belong to the second side which doesn't yet exist.
            // Open a second side with side index 1
            CSK_LOG_DEBUG("Setting second side of a connection");
            sideIndex = 1;
            tcpReassemblyData->twoSides[sideIndex].srcIP = srcIP;
            tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;
            tcpReassemblyData->numOfSides++;
            first = true;
        }
    }
    // if there are already 2 sides open for this connection
    else if (tcpReassemblyData->numOfSides == 2)
    {
        // check if packet matches side 0
        if (tcpReassemblyData->twoSides[0].srcPort == srcPort && tcpReassemblyData->twoSides[0].srcIP == srcIP)
        {
            sideIndex = 0;
        }
        // check if packet matches side 1
        else if (tcpReassemblyData->twoSides[1].srcPort == srcPort && tcpReassemblyData->twoSides[1].srcIP == srcIP)
        {
            sideIndex = 1;
        }
        // packet doesn't match either side
        else
        {
            CSK_LOG_ERROR("Error occurred - packet doesn't match either side of the connection!");
            return Error_PacketDoesNotMatchFlow;
        }
    }
    else
    {
        CSK_LOG_ERROR("Error occurred - connection has more than 2 sides!");
        return Error_PacketDoesNotMatchFlow;
    }

    // if this side already got FIN or RST packet before, ignore this packet
    if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
    {
        if (!tcpReassemblyData->twoSides[1 - sideIndex].gotFinOrRst && isRst)
        {
            handleFinOrRst(tcpReassemblyData, 1 - sideIndex, flowKey, isRst);
            return FIN_RSTWithNoData;
        }

        CSK_LOG_DEBUG("Got a packet after FIN or RST were already seen on this "
                      "side (%d). Ignoring this packet",
                      static_cast<int>(sideIndex));

        return Ignore_PacketOfClosedFlow;
    }

    // handle FIN/RST packets that don't contain additional TCP data
    if (isFinOrRst && tcpPayloadSize == 0)
    {
        CSK_LOG_DEBUG("Got FIN or RST packet without data on side %d", sideIndex);

        handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
        return FIN_RSTWithNoData;
    }

    // check if this packet contains data from a different side
    if (config_.enableBaseBufferClear && !first && tcpPayloadSize > 0 &&
        tcpReassemblyData->prevSide != -1 &&
        tcpReassemblyData->prevSide != sideIndex &&
        tcpReassemblyData->twoSides[tcpReassemblyData->prevSide].tcpFragments.size() > 0)
    {
        CSK_LOG_DEBUG("Seeing a first data packet from a different side. "
                      "Previous side was %d, current side is %d",
                      static_cast<int>(tcpReassemblyData->prevSide),
                      static_cast<int>(sideIndex));
        checkOutOfOrderFragments(tcpReassemblyData, tcpReassemblyData->prevSide, true);
    }
    tcpReassemblyData->prevSide = sideIndex;

    // extract sequence value from packet
    uint32_t sequence = tcpHeader.seqNum();

    // if it's the first packet we see on this side of the connection
    if (first)
    {
        CSK_LOG_DEBUG("First data from this side of the connection");

        // set initial sequence
        tcpReassemblyData->twoSides[sideIndex].sequence = sequence + tcpPayloadSize;
        if (tcpHeader.isSYN())
            tcpReassemblyData->twoSides[sideIndex].sequence++;

        // send data to the callback
        if (tcpPayloadSize != 0 && callbacks_.onMessageReady != nullptr)
        {
            TcpStreamData streamData(
                packet->getPayloadData(layer), tcpPayloadSize, 0, tcpReassemblyData->connData, currTime);
            callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
        }
        status = TcpMessageHandled;

        // handle case where this packet is FIN or RST
        if (isFinOrRst)
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

        return status;
    }

    // if packet sequence is smaller than expected - retransmission
    if (SEQ_LT(sequence, tcpReassemblyData->twoSides[sideIndex].sequence))
    {
        CSK_LOG_DEBUG("Found new data with the sequence lower than expected");

        uint32_t newSequence = sequence + tcpPayloadSize;

        if (SEQ_GT(newSequence, tcpReassemblyData->twoSides[sideIndex].sequence))
        {
            uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - sequence;

            CSK_LOG_DEBUG("Although sequence is lower than expected payload "
                          "is long enough to contain new data. Calling the "
                          "callback with the new data");

            tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize - newLength;

            if (callbacks_.onMessageReady != nullptr)
            {
                TcpStreamData streamData(packet->getPayloadData(layer) + newLength,
                                         tcpPayloadSize - newLength,
                                         0,
                                         tcpReassemblyData->connData,
                                         currTime);
                callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
            }
            status = TcpMessageHandled;
        }
        else
        {
            status = Ignore_Retransimission;
        }

        if (isFinOrRst)
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

        return status;
    }

    // if packet sequence is exactly as expected - the "good" case
    else if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
    {
        if (tcpPayloadSize == 0)
        {
            CSK_LOG_DEBUG("Payload length is 0, doing nothing");

            if (isFinOrRst)
            {
                handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
                status = FIN_RSTWithNoData;
            }
            else
            {
                status = Ignore_PacketWithNoData;
            }

            return status;
        }

        CSK_LOG_DEBUG("Found new data with expected sequence. Calling the callback");

        tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize;

        if (tcpHeader.isSYN())
            tcpReassemblyData->twoSides[sideIndex].sequence++;

        if (callbacks_.onMessageReady != nullptr)
        {
            TcpStreamData streamData(
                packet->getPayloadData(layer), tcpPayloadSize, 0, tcpReassemblyData->connData, currTime);
            callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
        }
        status = TcpMessageHandled;

        checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);

        if (isFinOrRst)
        {
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
        }

        return status;
    }

    // out-of-order packet
    else
    {
        if (tcpPayloadSize == 0)
        {
            CSK_LOG_DEBUG("Payload length is 0, doing nothing");

            if (isFinOrRst)
            {
                handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
                status = FIN_RSTWithNoData;
            }
            else
            {
                status = Ignore_PacketWithNoData;
            }

            return status;
        }

        TcpFragment* newTcpFrag =
            fragmentPool_->acquire(sequence, packet->getPayloadData(layer), tcpPayloadSize, currTime);

        if (!newTcpFrag)
        {
            CSK_LOG_WARNING("Fragment pool exhausted! Attempting cleanup...");
            checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true);

            newTcpFrag = fragmentPool_->acquire(sequence, packet->getPayloadData(layer), tcpPayloadSize, currTime);

            if (!newTcpFrag)
            {
                CSK_LOG_ERROR("Cannot allocate fragment even after cleanup!");
                return Error_NoMemory;
            }
        }

        auto& fragMap = tcpReassemblyData->twoSides[sideIndex].tcpFragments;

        auto it = fragMap.find(sequence);
        if (it != fragMap.end())
        {
            CSK_LOG_DEBUG("Retransmission detected for SEQ %u, replacing old fragment", sequence);
            fragmentPool_->release(it->second);
            it->second = newTcpFrag;
        }
        else
        {
            fragMap[sequence] = newTcpFrag;
        }

        CSK_LOG_DEBUG("Found out-of-order packet and added a new TCP fragment with size "
                      "%zu to the out-of-order list of side %d",
                      tcpPayloadSize,
                      static_cast<int>(sideIndex));
        status = OutOfOrderTcpMessageBuffered;

        if (config_.maxOutOfOrder > 0 &&
            tcpReassemblyData->twoSides[sideIndex].tcpFragments.size() > config_.maxOutOfOrder)
        {
            checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);
        }

        if (isFinOrRst)
        {
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
        }

        return status;
    }
}

void TcpReassembly::handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey, bool isRst)
{
    if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
        return;

    CSK_LOG_DEBUG("Handling FIN or RST packet on side %d", static_cast<int>(sideIndex));

    tcpReassemblyData->twoSides[sideIndex].gotFinOrRst = true;

    int otherSideIndex = 1 - sideIndex;
    if (tcpReassemblyData->twoSides[otherSideIndex].gotFinOrRst)
    {
        closeConnectionInternal(flowKey, TcpReassemblyConnectionClosedByFIN_RST);
        return;
    }
    else
        checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true);

    if (isRst)
        closeConnectionInternal(flowKey, TcpReassemblyConnectionClosedByFIN_RST);
}

void TcpReassembly::checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex,
                                             bool cleanWholeFragList)
{
    if (m_ProcessingOutOfOrder)
    {
        return;
    }

    OutOfOrderProcessingGuard guard(m_ProcessingOutOfOrder);

    auto& curSideData = tcpReassemblyData->twoSides[sideIndex];
    auto& fragMap = curSideData.tcpFragments;
    uint32_t expected = curSideData.sequence;

    bool foundSomething = true;
    while (foundSomething)
    {
        foundSomething = false;

        auto it = fragMap.begin();
        while (it != fragMap.end())
        {
            TcpFragment* frag = it->second;
            uint32_t fragEnd = frag->sequence + static_cast<uint32_t>(frag->dataLength);

            if (frag->sequence <= expected && fragEnd > expected)
            {
                uint32_t offset = expected - frag->sequence;
                size_t newLen = frag->dataLength - offset;

                CSK_LOG_DEBUG("Found fragment overlapping expected sequence. "
                              "Fragment [%u, %u], expected %u, new data [%u, %u]",
                              frag->sequence,
                              fragEnd,
                              expected,
                              expected,
                              expected + static_cast<uint32_t>(newLen));

                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(
                        frag->data + offset, newLen, 0, tcpReassemblyData->connData, frag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                expected += static_cast<uint32_t>(newLen);
                curSideData.sequence = expected;

                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            if (fragEnd <= expected)
            {
                CSK_LOG_DEBUG(
                    "Retransmission detected: fragment [%u, %u], expected %u", frag->sequence, fragEnd, expected);

                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            if (frag->sequence == expected)
            {
                CSK_LOG_DEBUG("Found in-order fragment [%u, %u], expected %u", frag->sequence, fragEnd, expected);

                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(
                        frag->data, frag->dataLength, 0, tcpReassemblyData->connData, frag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                expected += static_cast<uint32_t>(frag->dataLength);
                curSideData.sequence = expected;

                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            ++it;
        }

        if (cleanWholeFragList && !fragMap.empty())
        {
            auto firstIt = fragMap.begin();
            TcpFragment* firstFrag = firstIt->second;

            if (firstFrag->sequence > expected)
            {
                uint32_t missingLen = firstFrag->sequence - expected;

                CSK_LOG_DEBUG("Processing missing data: expected %u, first fragment %u, "
                              "missing %u bytes on side %d",
                              expected,
                              firstFrag->sequence,
                              missingLen,
                              sideIndex);

                std::string missingText = "[" + std::to_string(missingLen) + " bytes missing]";

                std::vector<uint8_t> dataWithMissing;
                dataWithMissing.reserve(missingText.size() + firstFrag->dataLength);
                dataWithMissing.insert(dataWithMissing.end(), missingText.begin(), missingText.end());
                dataWithMissing.insert(dataWithMissing.end(), firstFrag->data, firstFrag->data + firstFrag->dataLength);

                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(dataWithMissing.data(),
                                             dataWithMissing.size(),
                                             missingLen,
                                             tcpReassemblyData->connData,
                                             firstFrag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                expected = firstFrag->sequence + static_cast<uint32_t>(firstFrag->dataLength);
                curSideData.sequence = expected;

                fragmentPool_->release(firstFrag);
                fragMap.erase(firstIt);
                foundSomething = true;
                continue;
            }
        }

        if (!cleanWholeFragList && config_.maxOutOfOrder > 0 && fragMap.size() > config_.maxOutOfOrder)
        {
            CSK_LOG_DEBUG("Out-of-order fragment limit exceeded (%zu > %u). "
                          "Processing as missing data.",
                          fragMap.size(),
                          config_.maxOutOfOrder);

            cleanWholeFragList = true;
            foundSomething = true;
            continue;
        }
    }

    if (!fragMap.empty())
    {
        CSK_LOG_DEBUG("checkOutOfOrderFragments finished. Side %d, expected %u, "
                      "%zu fragments remaining in map",
                      sideIndex,
                      curSideData.sequence,
                      fragMap.size());
    }
}

void TcpReassembly::closeConnection(uint32_t flowKey)
{
    closeConnectionInternal(flowKey, TcpReassemblyConnectionClosedManually);
}

void TcpReassembly::closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason)
{
    auto* session = sessionManager_.find(flowKey);
    if (!session)
    {
        CSK_LOG_ERROR("Cannot close flow with key %lx: cannot find flow", flowKey);
        return;
    }

    auto* tcpReassemblyData = sessionManager_.getContext<TcpReassemblyData>(session);
    if (!tcpReassemblyData)
        return;

    if (tcpReassemblyData->closed)
        return;

    CSK_LOG_DEBUG("Closing connection with flow key %lx", flowKey);

    checkOutOfOrderFragments(tcpReassemblyData, 0, true);
    checkOutOfOrderFragments(tcpReassemblyData, 1, true);

    for (auto& pair : tcpReassemblyData->twoSides[0].tcpFragments)
    {
        fragmentPool_->release(pair.second);
    }
    tcpReassemblyData->twoSides[0].tcpFragments.clear();

    for (auto& pair : tcpReassemblyData->twoSides[1].tcpFragments)
    {
        fragmentPool_->release(pair.second);
    }
    tcpReassemblyData->twoSides[1].tcpFragments.clear();

    if (callbacks_.onConnectionClose != nullptr)
    {
        callbacks_.onConnectionClose(tcpReassemblyData->connData, reason, m_UserCookie);
    }

    tcpReassemblyData->closed = true;
    
    // Remove session from SessionManager
    sessionManager_.removeSession(flowKey);

    CSK_LOG_DEBUG("Connection with flow key %lx is closed", flowKey);
}

void TcpReassembly::closeAllConnections()
{
    CSK_LOG_DEBUG("Closing all flows");

    sessionManager_.forEachSession([this](typename SessionManager<uint32_t, std::tuple<TcpReassemblyData>>::Session* session)
    {
        auto* tcpReassemblyData = sessionManager_.getContext<TcpReassemblyData>(session);
        if (!tcpReassemblyData || tcpReassemblyData->closed)
            return;

        uint32_t flowKey = session->key;
        CSK_LOG_DEBUG("Closing connection with flow key %lx", flowKey);

        checkOutOfOrderFragments(tcpReassemblyData, 0, true);
        checkOutOfOrderFragments(tcpReassemblyData, 1, true);

        if (callbacks_.onConnectionClose != nullptr)
        {
            callbacks_.onConnectionClose(tcpReassemblyData->connData, 
                                        TcpReassemblyConnectionClosedManually, 
                                        m_UserCookie);
        }

        tcpReassemblyData->closed = true;
    });

    // Cleanup all sessions
    sessionManager_.cleanup();
}

} // namespace snet::layers