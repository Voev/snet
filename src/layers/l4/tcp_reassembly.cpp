#include <cstring>
#include <snet/layers/l4/tcp_reassembly.hpp>
#include <snet/layers/checksums.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/log/log.hpp>

using namespace casket;

#define PURGE_FREQ_SECS 1

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
    m_PurgeTimepoint = time(nullptr) + PURGE_FREQ_SECS;
}

TcpReassembly::ReassemblyStatus TcpReassembly::reassemblePacket(Packet* packet)
{
    // automatic cleanup
    if (config_.removeConnInfo)
    {
        if (time(nullptr) >= m_PurgeTimepoint)
        {
            purgeClosedConnections();
            m_PurgeTimepoint = time(nullptr) + PURGE_FREQ_SECS;
        }
    }

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

    // find the connection in the connection map
    ConnectionList::iterator iter = m_ConnectionList.find(flowKey);

    if (iter == m_ConnectionList.end())
    {
        // if it's a packet of a new connection, create a TcpReassemblyData
        // object and add it to the active connection list
        std::pair<ConnectionList::iterator, bool> pair =
            m_ConnectionList.insert(std::make_pair(flowKey, TcpReassemblyData()));
        tcpReassemblyData = &pair.first->second;
        tcpReassemblyData->connData.tuple = ConnectionTuple({srcIP, tcpHeader.srcPort()}, {dstIP, tcpHeader.dstPort()});
        tcpReassemblyData->connData.start_time = currTime;

        m_ConnectionInfo[flowKey] = tcpReassemblyData->connData;

        // fire connection start callback
        if (callbacks_.onConnectionStart != nullptr)
            callbacks_.onConnectionStart(tcpReassemblyData->connData, m_UserCookie);
    }
    else // connection already exists
    {
        // if this packet belongs to a connection that was already closed (for
        // example: data packet that comes after FIN), ignore it.
        if (iter->second.closed)
        {
            CSK_LOG_DEBUG("Ignoring packet of already closed flow [0x%lx]", flowKey);
            return Ignore_PacketOfClosedFlow;
        }

        tcpReassemblyData = &iter->second;

        if (currTime > tcpReassemblyData->connData.end_time)
        {
            tcpReassemblyData->connData.end_time = currTime;
            m_ConnectionInfo[flowKey].end_time = currTime;
        }
    }

    int8_t sideIndex = -1;
    bool first = false;

    // calculate packet's source port
    uint16_t srcPort = tcpHeader.srcPort();

    // if this is a new connection and it's the first packet we see on that
    // connection
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
    // if there is already one side in this connection (which will be at side
    // index 0)
    else if (tcpReassemblyData->numOfSides == 1)
    {
        // check if packet belongs to that side
        if (tcpReassemblyData->twoSides[0].srcPort == srcPort && tcpReassemblyData->twoSides[0].srcIP == srcIP)
        {
            sideIndex = 0;
        }
        else
        {
            // this means packet belong to the second side which doesn't yet
            // exist. Open a second side with side index 1
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
        // packet doesn't match either side. This case doesn't make sense but
        // it's handled anyway. Packet will be ignored
        else
        {
            CSK_LOG_ERROR("Error occurred - packet doesn't match either side "
                          "of the connection!");
            return Error_PacketDoesNotMatchFlow;
        }
    }
    // there are more than 2 side - this case doesn't make sense and shouldn't
    // happen, but handled anyway. Packet will be ignored
    else
    {
        CSK_LOG_ERROR("Error occurred - connection has more than 2 sides!");
        return Error_PacketDoesNotMatchFlow;
    }

    // if this side already got FIN or RST packet before, ignore this packet as
    // this side is considered closed
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

    // check if this packet contains data from a different side than the side
    // seen before. If this is the case then treat the out-of-order packet list
    // as missing data and send them to the user (callback) together with an
    // other side means the previous message was probably already received and a
    // indication that some data was missing. Why? because a new packet from the
    // new message is starting. In this case out-of-order packets are probably
    // actually missing data For example: let's assume these are HTTP messages.
    // If we're seeing the first packet of a response this means the server has
    // already received the full request and is now starting to send the
    // response. So if we still have out-of-order packets from the request it
    // probably means that some packets were lost during the capture. So we
    // don't expect the client to continue sending packets of the previous
    // request, so we'll treat the out-of-order packets as missing data
    //
    // I'm aware that there are edge cases where the situation I described above
    // is not true, but at some point we must clean the out-of-order packet list
    // to avoid memory leak. I decided to do what Wireshark does and clean this
    // list when starting to see a message from the other side

    // Since there are instances where this buffer clear condition can lead to
    // declaration of excessive missing packets. Hence user should have a config
    // file parameter to disable this and purely rely on max buffer size
    // condition. As none of them are perfect solutions this will give user a
    // little more control over it.

    if (config_.enableBaseBufferClear && !first && tcpPayloadSize > 0 && tcpReassemblyData->prevSide != -1 &&
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

        // handle case where this packet is FIN or RST (although it's unlikely)
        if (isFinOrRst)
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

        // return - nothing else to do here
        return status;
    }

    // if packet sequence is smaller than expected - this means that part or all
    // of the TCP data is being re-transmitted
    if (SEQ_LT(sequence, tcpReassemblyData->twoSides[sideIndex].sequence))
    {
        CSK_LOG_DEBUG("Found new data with the sequence lower than expected");

        // calculate the sequence after this packet to see if this TCP payload
        // contains also new data
        uint32_t newSequence = sequence + tcpPayloadSize;

        // this means that some of payload is new
        if (SEQ_GT(newSequence, tcpReassemblyData->twoSides[sideIndex].sequence))
        {
            // calculate the size of the new data
            uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - sequence;

            CSK_LOG_DEBUG("Although sequence is lower than expected payload "
                          "is long enough to contain new data. Calling the "
                          "callback with the new data");

            // update the sequence for this side to include the new data that
            // was seen
            tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize - newLength;

            // send only the new data to the callback
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

        // handle case where this packet is FIN or RST
        if (isFinOrRst)
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

        // return - nothing else to do here
        return status;
    }

    // if packet sequence is exactly as expected - this is the "good" case and
    // the most common one
    else if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
    {
        // if TCP data size is 0 - nothing to do
        if (tcpPayloadSize == 0)
        {
            CSK_LOG_DEBUG("Payload length is 0, doing nothing");

            // handle case where this packet is FIN or RST
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

        // update the sequence for this side to include TCP data from this
        // packet
        tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize;

        // if this is a SYN packet - add +1 to the sequence
        if (tcpHeader.isSYN())
            tcpReassemblyData->twoSides[sideIndex].sequence++;

        // send the data to the callback
        if (callbacks_.onMessageReady != nullptr)
        {
            TcpStreamData streamData(
                packet->getPayloadData(layer), tcpPayloadSize, 0, tcpReassemblyData->connData, currTime);
            callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
        }
        status = TcpMessageHandled;

        // now that we've seen new data, go over the list of out-of-order
        // packets and see if one or more of them fits now
        checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);

        // handle case where this packet is FIN or RST
        if (isFinOrRst)
        {
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
        }

        // return - nothing else to do here
        return status;
    }

    // this case means sequence size of the packet is higher than expected which
    // means the packet is out-of-order or some packets were lost (missing
    // data). we don't know which of the 2 cases it is at this point so we just
    // add this data to the out-of-order packet list
    else
    {
        // if TCP data size is 0 - nothing to do
        if (tcpPayloadSize == 0)
        {
            CSK_LOG_DEBUG("Payload length is 0, doing nothing");

            // handle case where this packet is FIN or RST
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

        //  ВСТАВКА В MAP ======

        auto& fragMap = tcpReassemblyData->twoSides[sideIndex].tcpFragments;

        // Проверяем ретрансмиссию
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

        // check if we've stored too many out-of-order fragments; if so,
        // consider missing packets lost and continue processing until the
        // number of stored fragments is lower than the acceptable limit again
        if (config_.maxOutOfOrder > 0 &&
            tcpReassemblyData->twoSides[sideIndex].tcpFragments.size() > config_.maxOutOfOrder)
        {
            checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);
        }

        // handle case where this packet is FIN or RST
        if (isFinOrRst)
        {
            handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
        }

        return status;
    }
}

void TcpReassembly::handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey, bool isRst)
{
    // if this side already saw a FIN or RST packet, do nothing and return
    if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
        return;

    CSK_LOG_DEBUG("Handling FIN or RST packet on side %d", static_cast<int>(sideIndex));

    // set FIN/RST flag for this side
    tcpReassemblyData->twoSides[sideIndex].gotFinOrRst = true;

    // check if the other side also sees FIN or RST packet. If so - just close
    // the flow. Otherwise - clear the out-of-order packets for this side
    int otherSideIndex = 1 - sideIndex;
    if (tcpReassemblyData->twoSides[otherSideIndex].gotFinOrRst)
    {
        closeConnectionInternal(flowKey, TcpReassemblyConnectionClosedByFIN_RST);
        return;
    }
    else
        checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true);

    // and if it's a rst, close the flow unilaterally
    if (isRst)
        closeConnectionInternal(flowKey, TcpReassemblyConnectionClosedByFIN_RST);
}

void TcpReassembly::checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex,
                                             bool cleanWholeFragList)
{
    // =========================================================================
    // 1. ЗАЩИТА ОТ РЕКУРСИИ
    // =========================================================================
    // Если мы уже обрабатываем out-of-order фрагменты, выходим.
    // Это предотвращает рекурсивные вызовы (например, если коллбэк вызывает
    // reassemblePacket, который снова вызывает checkOutOfOrderFragments).
    if (m_ProcessingOutOfOrder)
    {
        return;
    }

    // RAII guard: устанавливает m_ProcessingOutOfOrder = true при входе
    // и автоматически сбрасывает в false при выходе из функции.
    OutOfOrderProcessingGuard guard(m_ProcessingOutOfOrder);

    // =========================================================================
    // 2. ПОЛУЧАЕМ ССЫЛКИ НА ДАННЫЕ
    // =========================================================================
    auto& curSideData = tcpReassemblyData->twoSides[sideIndex];
    auto& fragMap = curSideData.tcpFragments; // std::map<uint32_t, TcpFragment*>
    uint32_t expected = curSideData.sequence;

    // =========================================================================
    // 3. ОСНОВНОЙ ЦИКЛ
    // =========================================================================
    // Повторяем, пока находим фрагменты, которые можно обработать.
    // Это итеративный подход вместо рекурсивного.
    bool foundSomething = true;
    while (foundSomething)
    {
        foundSomething = false;

        // =====================================================================
        // 3.1. ПРОХОД ПО ВСЕМ ФРАГМЕНТАМ В MAP
        // =====================================================================
        // map уже отсортирован по SEQ, поэтому мы обходим фрагменты по порядку.
        auto it = fragMap.begin();
        while (it != fragMap.end())
        {
            TcpFragment* frag = it->second;
            uint32_t fragEnd = frag->sequence + static_cast<uint32_t>(frag->dataLength);

            // ----------------------------------------------------------------
            // СЛУЧАЙ 1: Фрагмент перекрывает expected (частично новые данные)
            // ----------------------------------------------------------------
            // Пример: expected = 1000, fragment = [990, 1010]
            // Новые данные: [1000, 1010] (10 байт)
            if (frag->sequence <= expected && fragEnd > expected)
            {
                // Вычисляем смещение и размер новых данных
                uint32_t offset = expected - frag->sequence;
                size_t newLen = frag->dataLength - offset;

                CSK_LOG_DEBUG("Found fragment overlapping expected sequence. "
                              "Fragment [%u, %u], expected %u, new data [%u, %u]",
                              frag->sequence,
                              fragEnd,
                              expected,
                              expected,
                              expected + static_cast<uint32_t>(newLen));

                // Отправляем только новые данные в коллбэк
                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(
                        frag->data + offset, newLen, 0, tcpReassemblyData->connData, frag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                // Обновляем expected до конца новых данных
                expected += static_cast<uint32_t>(newLen);
                curSideData.sequence = expected;

                // Возвращаем фрагмент в пул и удаляем из map
                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            // ----------------------------------------------------------------
            // СЛУЧАЙ 2: Фрагмент полностью внутри expected (ретрансмиссия)
            // ----------------------------------------------------------------
            // Пример: expected = 1000, fragment = [980, 990]
            // Все данные уже получены — это ретрансмиссия.
            if (fragEnd <= expected)
            {
                CSK_LOG_DEBUG(
                    "Retransmission detected: fragment [%u, %u], expected %u", frag->sequence, fragEnd, expected);

                // Просто удаляем фрагмент, данные уже отправлены
                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            // ----------------------------------------------------------------
            // СЛУЧАЙ 3: Фрагмент начинается ровно с expected (in-order)
            // ----------------------------------------------------------------
            // Пример: expected = 1000, fragment = [1000, 1020]
            if (frag->sequence == expected)
            {
                CSK_LOG_DEBUG("Found in-order fragment [%u, %u], expected %u", frag->sequence, fragEnd, expected);

                // Отправляем все данные фрагмента
                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(
                        frag->data, frag->dataLength, 0, tcpReassemblyData->connData, frag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                // Обновляем expected
                expected += static_cast<uint32_t>(frag->dataLength);
                curSideData.sequence = expected;

                // Возвращаем фрагмент в пул и удаляем из map
                fragmentPool_->release(frag);
                it = fragMap.erase(it);
                foundSomething = true;
                continue;
            }

            // Фрагмент имеет SEQ > expected — переходим к следующему
            ++it;
        }

        // =====================================================================
        // 3.2. ОЧИСТКА ВСЕГО СПИСКА (обработка как missing data)
        // =====================================================================
        // Если cleanWholeFragList == true, обрабатываем все оставшиеся
        // фрагменты как missing data. Это происходит в двух случаях:
        //   1. Пришёл FIN/RST пакет
        //   2. Превышен лимит out-of-order фрагментов
        //   3. Пакет с другой стороны соединения
        if (cleanWholeFragList && !fragMap.empty())
        {
            auto firstIt = fragMap.begin();
            TcpFragment* firstFrag = firstIt->second;

            // Проверяем, есть ли пропуск данных
            if (firstFrag->sequence > expected)
            {
                uint32_t missingLen = firstFrag->sequence - expected;

                CSK_LOG_DEBUG("Processing missing data: expected %u, first fragment %u, "
                              "missing %u bytes on side %d",
                              expected,
                              firstFrag->sequence,
                              missingLen,
                              sideIndex);

                // Формируем сообщение о пропущенных данных
                std::string missingText = "[" + std::to_string(missingLen) + " bytes missing]";

                // Собираем сообщение: "[X bytes missing]" + данные фрагмента
                std::vector<uint8_t> dataWithMissing;
                dataWithMissing.reserve(missingText.size() + firstFrag->dataLength);
                dataWithMissing.insert(dataWithMissing.end(), missingText.begin(), missingText.end());
                dataWithMissing.insert(dataWithMissing.end(), firstFrag->data, firstFrag->data + firstFrag->dataLength);

                // Отправляем в коллбэк
                if (callbacks_.onMessageReady != nullptr)
                {
                    TcpStreamData streamData(dataWithMissing.data(),
                                             dataWithMissing.size(),
                                             missingLen,
                                             tcpReassemblyData->connData,
                                             firstFrag->timestamp);
                    callbacks_.onMessageReady(sideIndex, streamData, m_UserCookie);
                }

                // Обновляем expected до конца фрагмента
                expected = firstFrag->sequence + static_cast<uint32_t>(firstFrag->dataLength);
                curSideData.sequence = expected;

                // Возвращаем фрагмент в пул и удаляем из map
                fragmentPool_->release(firstFrag);
                fragMap.erase(firstIt);
                foundSomething = true;
                continue;
            }
        }

        // =====================================================================
        // 3.3. ПРОВЕРКА ЛИМИТА OUT-OF-ORDER ФРАГМЕНТОВ
        // =====================================================================
        // Если накопилось слишком много out-of-order фрагментов,
        // принудительно обрабатываем их как missing data.
        if (!cleanWholeFragList && config_.maxOutOfOrder > 0 && fragMap.size() > config_.maxOutOfOrder)
        {
            CSK_LOG_DEBUG("Out-of-order fragment limit exceeded (%zu > %u). "
                          "Processing as missing data.",
                          fragMap.size(),
                          config_.maxOutOfOrder);

            // Устанавливаем флаг и продолжаем цикл
            cleanWholeFragList = true;
            foundSomething = true;
            continue;
        }
    }

    // =========================================================================
    // 4. LOG: ИТОГОВОЕ СОСТОЯНИЕ
    // =========================================================================
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
    ConnectionList::iterator iter = m_ConnectionList.find(flowKey);
    if (iter == m_ConnectionList.end())
    {
        CSK_LOG_ERROR("Cannot close flow with key %lx: cannot find flow", flowKey);
        return;
    }

    TcpReassemblyData& tcpReassemblyData = iter->second;

    if (tcpReassemblyData.closed)
        return;

    CSK_LOG_DEBUG("Closing connection with flow key %lx", flowKey);

    checkOutOfOrderFragments(&tcpReassemblyData, 0, true);
    checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

    for (auto& pair : tcpReassemblyData.twoSides[0].tcpFragments)
    {
        fragmentPool_->release(pair.second);
    }
    tcpReassemblyData.twoSides[0].tcpFragments.clear();

    for (auto& pair : tcpReassemblyData.twoSides[1].tcpFragments)
    {
        fragmentPool_->release(pair.second);
    }
    tcpReassemblyData.twoSides[1].tcpFragments.clear();

    if (callbacks_.onConnectionClose != nullptr)
    {
        callbacks_.onConnectionClose(tcpReassemblyData.connData, reason, m_UserCookie);
    }

    tcpReassemblyData.closed = true;
    insertIntoCleanupList(flowKey);

    CSK_LOG_DEBUG("Connection with flow key %lx is closed", flowKey);
}

void TcpReassembly::closeAllConnections()
{
    CSK_LOG_DEBUG("Closing all flows");

    ConnectionList::iterator iter = m_ConnectionList.begin(), iterEnd = m_ConnectionList.end();
    for (; iter != iterEnd; ++iter)
    {
        TcpReassemblyData& tcpReassemblyData = iter->second;

        if (tcpReassemblyData.closed) // the connection is already closed, skip it
            continue;

        uint32_t flowKey = tcpReassemblyData.connData.getFlowKey();
        CSK_LOG_DEBUG("Closing connection with flow key %lx", flowKey);

        CSK_LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
        checkOutOfOrderFragments(&tcpReassemblyData, 0, true);

        CSK_LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
        checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

        if (callbacks_.onConnectionClose != nullptr)
        {
            callbacks_.onConnectionClose(
                tcpReassemblyData.connData, TcpReassemblyConnectionClosedManually, m_UserCookie);
        }

        tcpReassemblyData.closed = true; // mark the connection as closed
        insertIntoCleanupList(flowKey);

        CSK_LOG_DEBUG("Connection with flow key %lx is closed", flowKey);
    }
}

int TcpReassembly::isConnectionOpen(const ConnectionInfo& connection) const
{
    ConnectionList::const_iterator iter = m_ConnectionList.find(connection.getFlowKey());
    if (iter != m_ConnectionList.end())
        return iter->second.closed == false;

    return -1;
}

void TcpReassembly::insertIntoCleanupList(uint32_t flowKey)
{
    // m_CleanupList is a map with key of type time_t (expiration time). The
    // mapped type is a list that stores the flow keys to be cleared in certain
    // point of time. m_CleanupList.insert inserts an empty list if the
    // container does not already contain an element with an equivalent key,
    // otherwise this method returns an iterator to the element that prevents
    // insertion.
    std::pair<CleanupList::iterator, bool> pair =
        m_CleanupList.insert(std::make_pair(time(nullptr) + config_.closeDelaySec, CleanupList::mapped_type()));

    // getting the reference to list
    CleanupList::mapped_type& keysList = pair.first->second;
    keysList.push_front(flowKey);
}

uint32_t TcpReassembly::purgeClosedConnections(uint32_t maxNumToClean)
{
    uint32_t count = 0;

    if (maxNumToClean == 0)
        maxNumToClean = config_.maxCleanup;

    CleanupList::iterator iterTime = m_CleanupList.begin(), iterTimeEnd = m_CleanupList.upper_bound(time(nullptr));
    while (iterTime != iterTimeEnd && count < maxNumToClean)
    {
        CleanupList::mapped_type& keysList = iterTime->second;

        for (; !keysList.empty() && count < maxNumToClean; ++count)
        {
            CleanupList::mapped_type::const_reference key = keysList.front();
            m_ConnectionInfo.erase(key);
            m_ConnectionList.erase(key);
            keysList.pop_front();
        }

        if (keysList.empty())
            m_CleanupList.erase(iterTime++);
        else
            ++iterTime;
    }

    return count;
}

} // namespace snet::layers
