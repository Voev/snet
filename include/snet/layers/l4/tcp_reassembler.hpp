// tcp_reassembler_handler.hpp
#pragma once
#include <map>
#include <functional>
#include <memory>

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_stream.hpp>
#include <snet/layers/l4/tcp_fragment.hpp>
#include <snet/layers/l4/tcp_fragment_pool.hpp>
#include <snet/layers/l4/tcp_types.hpp>
#include <snet/layers/session_handler.hpp>

namespace snet::layers
{

// Контекст для TCP reassembler в SessionManager
struct TcpReassemblerContext
{
    static constexpr size_t MAX_INSTANCES = 1;

    struct OneSideData
    {
        IPAddress srcIP;
        uint16_t srcPort{0};
        uint32_t expectedSeq{0};
        std::map<uint32_t, TcpFragment*> tcpFragments;
        bool gotFinOrRst{false};
        uint64_t packetsReceived{0};
        uint64_t bytesReceived{0};

        void clear(TcpFragmentPool* pool)
        {
            for (auto& pair : tcpFragments)
            {
                pool->release(pair.second);
            }
            tcpFragments.clear();
            gotFinOrRst = false;
        }
    };

    bool closed{false};
    int8_t numOfSides{0};
    int8_t prevSide{-1};
    OneSideData twoSides[2];
    ConnectionInfo connData;
    uint64_t createdAt{0};
    uint64_t lastActivity{0};
    uint64_t totalBytesProcessed{0};

    void clear(TcpFragmentPool* pool)
    {
        twoSides[0].clear(pool);
        twoSides[1].clear(pool);
        closed = false;
        numOfSides = 0;
        prevSide = -1;
        totalBytesProcessed = 0;
    }
};

// Конфигурация для обработчика
struct TcpReassemblerHandlerConfig
{
    TcpFragmentPoolConfig poolConfig;
    uint32_t maxOutOfOrder{0};
    bool enableBaseBufferClear{true};
};

// Колбэки для внешнего мира
template <typename SessionType>
struct TcpReassemblerHandlerCallbacks
{
    using OnDataReady = std::function<void(SessionType* session, int8_t side, const TcpStreamData& data)>;

    using OnConnectionStart = std::function<void(SessionType* session, const ConnectionInfo& info)>;

    using OnConnectionClose =
        std::function<void(SessionType* session, const ConnectionInfo& info, ConnectionEndReason reason)>;

    OnDataReady onDataReady;
    OnConnectionStart onConnectionStart;
    OnConnectionClose onConnectionClose;
};

// TcpReassembler как ISessionHandler
template <typename SessionManagerType>
class TcpReassemblerHandler : public ISessionHandler<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using Key = typename SessionManagerType::Key;
    using Callbacks = TcpReassemblerHandlerCallbacks<Session>;

    explicit TcpReassemblerHandler(TcpReassemblerHandlerConfig config = {}, Callbacks callbacks = {})
        : config_(std::move(config))
        , callbacks_(std::move(callbacks))
        , fragmentPool_(std::make_unique<TcpFragmentPool>(config_.poolConfig))
    {
    }

    const char* name() const override
    {
        return "TcpReassemblerHandler";
    }

    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        // Проверяем, есть ли уже контекст
        if (this->template hasContext<TcpReassemblerContext>(session))
        {
            return true;
        }

        // Создаем контекст
        auto* ctx = this->template allocateContext<TcpReassemblerContext>();
        if (!ctx)
        {
            return false;
        }

        // Инициализируем
        ctx->clear(fragmentPool_.get());

        if (!this->template setContext<TcpReassemblerContext>(session, ctx))
        {
            this->template deallocateContext<TcpReassemblerContext>(ctx);
            return false;
        }

        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        // Получаем и очищаем контекст
        auto* ctx = this->template getContext<TcpReassemblerContext>(session);
        if (ctx)
        {
            ctx->clear(fragmentPool_.get());
            this->template removeContext<TcpReassemblerContext>(session);
        }

        return true;
    }

    PacketStatus processPacket(Session* session, layers::Packet* packet) override
    {
        if (!session || !packet)
        {
            return PacketStatus::Error_NoMemory;
        }

        // Получаем контекст
        auto* ctx = this->template getContext<TcpReassemblerContext>(session);
        if (!ctx)
        {
            return PacketStatus::Error_NoMemory;
        }

        // Извлекаем IP и TCP информацию
        IPAddress srcIP, dstIP;
        TCPHeader tcpHeader;
        const Layer* tcpLayer = nullptr;

        if (!extractPacketInfo(packet, srcIP, dstIP, tcpHeader, tcpLayer))
        {
            // Не TCP/IP пакет - передаем дальше по цепочке
            if (this->nextPacket(session, packet))
            {
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::NonTcpPacket;
        }

        auto timestamp = packet->getTimestamp().toTimePoint();
        auto timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()).count();

        // Вычисляем ключ
        Key flowKey = calculateFlowKey(srcIP, dstIP, tcpHeader);

        // Инициализация нового соединения
        bool isNewConnection = (ctx->numOfSides == 0);
        if (isNewConnection)
        {
            ctx->connData.tuple = ConnectionTuple({srcIP, tcpHeader.srcPort()}, {dstIP, tcpHeader.dstPort()});
            ctx->connData.start_time = timestamp;
            ctx->createdAt = timestampUs;

            if (callbacks_.onConnectionStart)
            {
                callbacks_.onConnectionStart(session, ctx->connData);
            }
        }

        // Обновляем активность
        ctx->lastActivity = timestampUs;
        if (timestamp > ctx->connData.end_time)
        {
            ctx->connData.end_time = timestamp;
        }

        // Проверяем закрытое соединение
        if (ctx->closed)
        {
            // Передаем дальше по цепочке
            if (this->nextPacket(session, packet))
            {
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::Ignore_PacketOfClosedFlow;
        }

        // Определяем сторону
        int8_t side = determineSide(ctx, srcIP, tcpHeader.srcPort());
        if (side < 0)
        {
            // Передаем дальше по цепочке
            if (this->nextPacket(session, packet))
            {
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::Error_PacketDoesNotMatchFlow;
        }

        auto& sideData = ctx->twoSides[side];
        sideData.packetsReceived++;

        // Проверяем FIN/RST на этой стороне
        if (sideData.gotFinOrRst)
        {
            if (!ctx->twoSides[1 - side].gotFinOrRst && tcpHeader.isRST())
            {
                handleFinOrRst(ctx, session, flowKey, 1 - side, true);
                // Передаем дальше по цепочке
                if (this->nextPacket(session, packet))
                {
                    return PacketStatus::TcpMessageHandled;
                }
                return PacketStatus::FIN_RSTWithNoData;
            }
            // Передаем дальше по цепочке
            if (this->nextPacket(session, packet))
            {
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::Ignore_PacketOfClosedFlow;
        }

        // Получаем данные
        size_t payloadLen = packet->getPayloadSize(tcpLayer);
        const uint8_t* payload = packet->getPayloadData(tcpLayer);

        bool isFin = tcpHeader.isFIN();
        bool isRst = tcpHeader.isRST();

        // FIN/RST без данных
        if ((isFin || isRst) && payloadLen == 0)
        {
            handleFinOrRst(ctx, session, flowKey, side, isRst);
            // Передаем дальше по цепочке
            if (this->nextPacket(session, packet))
            {
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::FIN_RSTWithNoData;
        }

        // Проверка смены стороны
        if (config_.enableBaseBufferClear && !isFirstPacket(ctx, side) && payloadLen > 0 && ctx->prevSide != -1 &&
            ctx->prevSide != side && !ctx->twoSides[ctx->prevSide].tcpFragments.empty())
        {

            checkOutOfOrderFragments(ctx, session, ctx->prevSide, true);
        }
        ctx->prevSide = side;

        // Обработка последовательности
        uint32_t seq = tcpHeader.seqNum();
        PacketStatus status = processSequence(
            ctx, session, side, seq, payload, payloadLen, tcpHeader.isSYN(), isFin, isRst, timestamp, flowKey);

        // Если пакет был обработан или проигнорирован - все равно передаем дальше
        // для других обработчиков в цепочке
        if (this->nextPacket(session, packet))
        {
            // Если дальше обработали - возвращаем успех
            return PacketStatus::TcpMessageHandled;
        }

        return status;
    }

    // ========== Управление ==========

    void setCallbacks(const Callbacks& callbacks)
    {
        callbacks_ = callbacks;
    }

    void setCallbacks(Callbacks&& callbacks)
    {
        callbacks_ = std::move(callbacks);
    }

    void closeConnection(Key flowKey)
    {
        auto* manager = this->getSessionManager();
        if (!manager)
            return;

        auto* session = manager->find(flowKey);
        if (!session)
            return;

        auto* ctx = this->template getContext<TcpReassemblerContext>(session);
        if (!ctx || ctx->closed)
            return;

        closeConnectionInternal(ctx, session, flowKey, ConnectionEndReason::TcpReassemblyConnectionClosedManually);
    }

    void closeAllConnections()
    {
        auto* manager = this->getSessionManager();
        if (!manager)
            return;

        manager->forEachSession(
            [this](Session* session)
            {
                auto* ctx = this->template getContext<TcpReassemblerContext>(session);
                if (!ctx || ctx->closed)
                    return;

                closeConnectionInternal(
                    ctx, session, session->key, ConnectionEndReason::TcpReassemblyConnectionClosedManually);
            });
    }

private:
    // ========== Вспомогательные методы ==========

    bool extractPacketInfo(layers::Packet* packet, IPAddress& srcIP, IPAddress& dstIP, TCPHeader& tcpHeader,
                           const Layer*& tcpLayer)
    {
        auto ipHeader = packet->getHeader<IPv4Header>(IPv4);
        if (!ipHeader.isValid())
            return false;

        srcIP = IPAddress(ipHeader.srcAddr());
        dstIP = IPAddress(ipHeader.dstAddr());

        tcpLayer = packet->findLayer(TCP);
        if (!tcpLayer)
            return false;

        tcpHeader = packet->getHeader<TCPHeader>(*tcpLayer);
        return true;
    }

    Key calculateFlowKey(const IPAddress& srcIP, const IPAddress& dstIP, const TCPHeader& tcpHeader)
    {
        return hash5Tuple(srcIP, dstIP, tcpHeader.srcPort(), tcpHeader.dstPort(), IPProtocol::TCP, false);
    }

    int8_t determineSide(TcpReassemblerContext* ctx, const IPAddress& srcIP, uint16_t srcPort)
    {
        if (ctx->numOfSides == 0)
        {
            ctx->twoSides[0].srcIP = srcIP;
            ctx->twoSides[0].srcPort = srcPort;
            ctx->numOfSides = 1;
            return 0;
        }

        if (ctx->twoSides[0].srcIP == srcIP && ctx->twoSides[0].srcPort == srcPort)
        {
            return 0;
        }

        if (ctx->numOfSides == 1)
        {
            ctx->twoSides[1].srcIP = srcIP;
            ctx->twoSides[1].srcPort = srcPort;
            ctx->numOfSides = 2;
            return 1;
        }

        if (ctx->twoSides[1].srcIP == srcIP && ctx->twoSides[1].srcPort == srcPort)
        {
            return 1;
        }

        return -1;
    }

    bool isFirstPacket(TcpReassemblerContext* ctx, int8_t side)
    {
        return ctx->twoSides[side].expectedSeq == 0;
    }

    PacketStatus processSequence(TcpReassemblerContext* ctx, Session* session, int8_t side, uint32_t seq,
                                 const uint8_t* payload, size_t len, bool isSyn, bool isFin, bool isRst,
                                 std::chrono::steady_clock::time_point timestamp, Key flowKey)
    {
        auto& sideData = ctx->twoSides[side];

#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)

        // Первый пакет на этой стороне
        if (sideData.expectedSeq == 0)
        {
            sideData.expectedSeq = seq + len;
            if (isSyn)
                sideData.expectedSeq++;

            deliverData(session, side, payload, len, ctx->connData, timestamp);
            ctx->totalBytesProcessed += len;
            sideData.bytesReceived += len;
            totalDataProcessed_ += len;
            totalPacketsProcessed_++;

            if (isFin || isRst)
            {
                handleFinOrRst(ctx, session, flowKey, side, isRst);
                return PacketStatus::FIN_RSTWithNoData;
            }
            return PacketStatus::TcpMessageHandled;
        }

        // Ретрансмиссия
        if (SEQ_LT(seq, sideData.expectedSeq))
        {
            uint32_t newSeq = seq + len;
            if (SEQ_GT(newSeq, sideData.expectedSeq))
            {
                uint32_t offset = sideData.expectedSeq - seq;
                uint32_t newLen = len - offset;

                sideData.expectedSeq += newLen;
                deliverData(session, side, payload + offset, newLen, ctx->connData, timestamp);
                ctx->totalBytesProcessed += newLen;
                sideData.bytesReceived += newLen;
                totalDataProcessed_ += newLen;
                totalPacketsProcessed_++;

                if (isFin || isRst)
                {
                    handleFinOrRst(ctx, session, flowKey, side, isRst);
                }
                return PacketStatus::TcpMessageHandled;
            }
            return PacketStatus::Ignore_Retransimission;
        }

        // Идеальный случай
        if (seq == sideData.expectedSeq)
        {
            if (len == 0)
            {
                if (isFin || isRst)
                {
                    handleFinOrRst(ctx, session, flowKey, side, isRst);
                    return PacketStatus::FIN_RSTWithNoData;
                }
                return PacketStatus::Ignore_PacketWithNoData;
            }

            sideData.expectedSeq += len;
            if (isSyn)
                sideData.expectedSeq++;

            deliverData(session, side, payload, len, ctx->connData, timestamp);
            ctx->totalBytesProcessed += len;
            sideData.bytesReceived += len;
            totalDataProcessed_ += len;
            totalPacketsProcessed_++;

            checkOutOfOrderFragments(ctx, session, side, false);

            if (isFin || isRst)
            {
                handleFinOrRst(ctx, session, flowKey, side, isRst);
            }
            return PacketStatus::TcpMessageHandled;
        }

        // Out-of-order
        if (len == 0)
        {
            if (isFin || isRst)
            {
                handleFinOrRst(ctx, session, flowKey, side, isRst);
                return PacketStatus::FIN_RSTWithNoData;
            }
            return PacketStatus::Ignore_PacketWithNoData;
        }

        // Буферизация out-of-order
        TcpFragment* newFrag = fragmentPool_->acquire(seq, payload, len, timestamp);
        if (!newFrag)
        {
            checkOutOfOrderFragments(ctx, session, side, true);
            newFrag = fragmentPool_->acquire(seq, payload, len, timestamp);
            if (!newFrag)
            {
                return PacketStatus::Error_NoMemory;
            }
        }

        auto& fragMap = sideData.tcpFragments;
        auto it = fragMap.find(seq);
        if (it != fragMap.end())
        {
            fragmentPool_->release(it->second);
            it->second = newFrag;
        }
        else
        {
            fragMap[seq] = newFrag;
            outOfOrderCount_++;
        }

        if (config_.maxOutOfOrder > 0 && fragMap.size() > config_.maxOutOfOrder)
        {
            checkOutOfOrderFragments(ctx, session, side, false);
        }

        if (isFin || isRst)
        {
            handleFinOrRst(ctx, session, flowKey, side, isRst);
        }

        return PacketStatus::OutOfOrderTcpMessageBuffered;

#undef SEQ_LT
#undef SEQ_GT
    }

    void checkOutOfOrderFragments(TcpReassemblerContext* ctx, Session* session, int8_t side, bool forceFlush)
    {
        if (processingOutOfOrder_)
            return;
        processingOutOfOrder_ = true;

        auto& sideData = ctx->twoSides[side];
        auto& fragMap = sideData.tcpFragments;
        uint32_t expected = sideData.expectedSeq;

        bool progress = true;
        while (progress)
        {
            progress = false;

            auto it = fragMap.begin();
            while (it != fragMap.end())
            {
                TcpFragment* frag = it->second;
                uint32_t fragEnd = frag->sequence + frag->dataLength;

                if (frag->sequence <= expected && fragEnd > expected)
                {
                    uint32_t offset = expected - frag->sequence;
                    size_t newLen = frag->dataLength - offset;

                    deliverData(session, side, frag->data + offset, newLen, ctx->connData, frag->timestamp);
                    ctx->totalBytesProcessed += newLen;
                    sideData.bytesReceived += newLen;
                    totalDataProcessed_ += newLen;

                    expected += static_cast<uint32_t>(newLen);
                    sideData.expectedSeq = expected;

                    fragmentPool_->release(frag);
                    it = fragMap.erase(it);
                    progress = true;
                    continue;
                }

                if (fragEnd <= expected)
                {
                    fragmentPool_->release(frag);
                    it = fragMap.erase(it);
                    progress = true;
                    continue;
                }

                if (frag->sequence == expected)
                {
                    deliverData(session, side, frag->data, frag->dataLength, ctx->connData, frag->timestamp);
                    ctx->totalBytesProcessed += frag->dataLength;
                    sideData.bytesReceived += frag->dataLength;
                    totalDataProcessed_ += frag->dataLength;

                    expected += frag->dataLength;
                    sideData.expectedSeq = expected;

                    fragmentPool_->release(frag);
                    it = fragMap.erase(it);
                    progress = true;
                    continue;
                }

                ++it;
            }

            if (forceFlush && !fragMap.empty())
            {
                auto firstIt = fragMap.begin();
                TcpFragment* firstFrag = firstIt->second;

                if (firstFrag->sequence > expected)
                {
                    uint32_t missing = firstFrag->sequence - expected;

                    std::string marker = "[" + std::to_string(missing) + " bytes missing]";
                    std::vector<uint8_t> dataWithMarker;
                    dataWithMarker.reserve(marker.size() + firstFrag->dataLength);
                    dataWithMarker.insert(dataWithMarker.end(), marker.begin(), marker.end());
                    dataWithMarker.insert(
                        dataWithMarker.end(), firstFrag->data, firstFrag->data + firstFrag->dataLength);

                    TcpStreamData streamData(
                        dataWithMarker.data(), dataWithMarker.size(), missing, ctx->connData, firstFrag->timestamp);

                    if (callbacks_.onDataReady)
                    {
                        callbacks_.onDataReady(session, side, streamData);
                    }

                    ctx->totalBytesProcessed += dataWithMarker.size();
                    totalDataProcessed_ += dataWithMarker.size();

                    expected = firstFrag->sequence + firstFrag->dataLength;
                    sideData.expectedSeq = expected;

                    fragmentPool_->release(firstFrag);
                    fragMap.erase(firstIt);
                    progress = true;
                }
            }
        }

        processingOutOfOrder_ = false;
    }

    void handleFinOrRst(TcpReassemblerContext* ctx, Session* session, Key flowKey, int8_t side, bool isRst)
    {
        if (ctx->twoSides[side].gotFinOrRst)
            return;

        ctx->twoSides[side].gotFinOrRst = true;

        int otherSide = 1 - side;
        if (ctx->twoSides[otherSide].gotFinOrRst || isRst)
        {
            closeConnectionInternal(ctx, session, flowKey, ConnectionEndReason::TcpReassemblyConnectionClosedByFIN_RST);
        }
        else
        {
            checkOutOfOrderFragments(ctx, session, side, true);
        }
    }

    void closeConnectionInternal(TcpReassemblerContext* ctx, Session* session, Key flowKey, ConnectionEndReason reason)
    {
        if (ctx->closed)
            return;

        checkOutOfOrderFragments(ctx, session, 0, true);
        checkOutOfOrderFragments(ctx, session, 1, true);

        ctx->twoSides[0].clear(fragmentPool_.get());
        ctx->twoSides[1].clear(fragmentPool_.get());

        if (callbacks_.onConnectionClose)
        {
            callbacks_.onConnectionClose(session, ctx->connData, reason);
        }

        ctx->closed = true;
    }

    void deliverData(Session* session, int8_t side, const uint8_t* data, size_t len, const ConnectionInfo& connInfo,
                     std::chrono::steady_clock::time_point timestamp)
    {
        if (len == 0)
            return;

        TcpStreamData streamData(data, len, 0, connInfo, timestamp);

        if (callbacks_.onDataReady)
        {
            callbacks_.onDataReady(session, side, streamData);
        }
    }

    TcpReassemblerHandlerConfig config_;
    Callbacks callbacks_;
    std::unique_ptr<TcpFragmentPool> fragmentPool_;
    bool processingOutOfOrder_{false};
    size_t outOfOrderCount_{0};
    size_t totalDataProcessed_{0};
    size_t totalPacketsProcessed_{0};
};

} // namespace snet::layers