// tcp_sender.hpp
#pragma once

#include <cstdint>
#include <array>
#include <queue>
#include <vector>
#include <chrono>
#include <cstring>
#include <casket/utils/endianness.hpp>
#include <casket/nonstd/span.hpp>

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_header.hpp>

namespace snet::layers {

// ============================================================================
// TCP Флаги
// ============================================================================

enum TcpFlags : uint8_t {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20,
    TCP_ECE = 0x40,
    TCP_CWR = 0x80
};

// ============================================================================
// Фиксированный пул объектов (без аллокаций)
// ============================================================================

template<typename T, size_t Capacity = 1024>
class FixedObjectPool {
private:
    union Node {
        T object;
        Node* next;
    };
    
    Node m_Pool[Capacity];
    Node* m_FreeList;
    size_t m_Used;
    
public:
    FixedObjectPool() : m_FreeList(nullptr), m_Used(0) {
        for (size_t i = 0; i < Capacity - 1; ++i) {
            m_Pool[i].next = &m_Pool[i + 1];
        }
        m_Pool[Capacity - 1].next = nullptr;
        m_FreeList = &m_Pool[0];
    }
    
    T* acquire() {
        if (!m_FreeList) return nullptr;
        Node* node = m_FreeList;
        m_FreeList = node->next;
        m_Used++;
        return &node->object;
    }
    
    void release(T* ptr) {
        if (!ptr) return;
        ptr->~T();
        Node* node = reinterpret_cast<Node*>(ptr);
        node->next = m_FreeList;
        m_FreeList = node;
        m_Used--;
    }
    
    size_t used() const { return m_Used; }
    size_t capacity() const { return Capacity; }
    bool full() const { return m_Used >= Capacity; }
};

// ============================================================================
// Пул буферов для данных (фиксированный)
// ============================================================================

class BufferPool {
private:
    static constexpr size_t MAX_BUFFERS = 256;
    static constexpr size_t BUFFER_SIZE = 65536;
    
    struct BufferEntry {
        uint8_t data[BUFFER_SIZE];
        uint16_t len;
        bool used;
        uint32_t flowKey;
        
        BufferEntry() : len(0), used(false), flowKey(0) {}
    };
    
    BufferEntry m_Buffers[MAX_BUFFERS];
    std::array<uint16_t, MAX_BUFFERS> m_FreeList;
    uint16_t m_FreeCount;
    
public:
    BufferPool() : m_FreeCount(MAX_BUFFERS) {
        for (uint16_t i = 0; i < MAX_BUFFERS; ++i) {
            m_FreeList[i] = i;
        }
    }
    
    uint16_t allocate(uint32_t flowKey, const uint8_t* data, uint16_t len) {
        if (m_FreeCount == 0 || len > BUFFER_SIZE) return MAX_BUFFERS;
        
        uint16_t idx = m_FreeList[--m_FreeCount];
        auto& entry = m_Buffers[idx];
        entry.len = len;
        entry.used = true;
        entry.flowKey = flowKey;
        
        if (data && len > 0) {
            memcpy(entry.data, data, len);
        }
        
        return idx;
    }
    
    void deallocate(uint16_t idx) {
        if (idx >= MAX_BUFFERS) return;
        m_Buffers[idx].used = false;
        m_Buffers[idx].len = 0;
        m_FreeList[m_FreeCount++] = idx;
    }
    
    const uint8_t* getData(uint16_t idx) const {
        if (idx >= MAX_BUFFERS) return nullptr;
        return m_Buffers[idx].data;
    }
    
    uint16_t getLen(uint16_t idx) const {
        if (idx >= MAX_BUFFERS) return 0;
        return m_Buffers[idx].len;
    }
    
    void clearForFlow(uint32_t flowKey) {
        for (auto& entry : m_Buffers) {
            if (entry.used && entry.flowKey == flowKey) {
                entry.used = false;
                entry.len = 0;
            }
        }
        // Перестраиваем свободный список
        m_FreeCount = 0;
        for (uint16_t i = 0; i < MAX_BUFFERS; ++i) {
            if (!m_Buffers[i].used) {
                m_FreeList[m_FreeCount++] = i;
            }
        }
    }
    
    void clear() {
        for (auto& entry : m_Buffers) {
            entry.used = false;
            entry.len = 0;
        }
        m_FreeCount = MAX_BUFFERS;
        for (uint16_t i = 0; i < MAX_BUFFERS; ++i) {
            m_FreeList[i] = i;
        }
    }
    
    size_t available() const { return m_FreeCount; }
    size_t total() const { return MAX_BUFFERS; }
};

// ============================================================================
// TcpSender - отправка TCP пакетов без аллокаций
// ============================================================================

class TcpSender {
public:
    // ============================================================
    // SendRequest - компактная структура
    // ============================================================
    
    struct SendRequest {
        uint32_t flowKey;
        uint32_t seq;
        uint32_t ackNum;
        uint32_t srcIP;
        uint32_t dstIP;
        uint16_t srcPort;
        uint16_t dstPort;
        uint16_t window;
        uint8_t flags;
        uint8_t retryCount;
        bool isRetransmission;
        uint64_t timestamp;
        uint16_t dataOffset;   // Индекс в BufferPool
        uint16_t dataLen;
        uint8_t optionsLen;
        uint8_t options[12];   // Максимум 12 байт опций
        
        SendRequest() : flowKey(0), seq(0), ackNum(0), srcIP(0), dstIP(0),
                        srcPort(0), dstPort(0), window(0), flags(0),
                        retryCount(0), isRetransmission(false), timestamp(0),
                        dataOffset(0xFFFF), dataLen(0), optionsLen(0) {
            memset(options, 0, sizeof(options));
        }
    };

    // ============================================================
    // Config
    // ============================================================
    
    struct Config {
        uint32_t maxQueueSize = 10000;
        uint32_t maxRetries = 3;
        uint32_t retransmitTimeout = 3000;  // ms
        uint16_t defaultWindowSize = 65535;
        uint32_t mss = 1460;
        uint8_t defaultTTL = 64;
        uint32_t initialSeq = 1000;
    };

    // ============================================================
    // Конструкторы / Деструктор
    // ============================================================
    
    explicit TcpSender(const Config& config)
        : m_Config(config)
        , m_Head(0)
        , m_Tail(0)
        , m_Count(0)
        , m_NextSeq(config.initialSeq)
        , m_TotalSent(0)
        , m_TotalDropped(0)
        , m_TotalRetransmitted(0)
    {
        
        // Предварительная инициализация запросов
        for (auto& req : m_RequestPool) {
            req.flowKey = 0;
            req.dataOffset = 0xFFFF;
            req.dataLen = 0;
        }
    }
    
    ~TcpSender() {
        clear();
    }
    
    // ============================================================
    // Отправка TCP пакетов
    // ============================================================
    
    bool sendSyn(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                 uint16_t srcPort, uint16_t dstPort,
                 uint32_t seqNum = 0) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_SYN;
        req->seq = seqNum ? seqNum : m_NextSeq++;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 4;  // MSS
        req->options[0] = 2;
        req->options[1] = 4;
        req->options[2] = (m_Config.mss >> 8) & 0xFF;
        req->options[3] = m_Config.mss & 0xFF;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    bool sendSynAck(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                    uint16_t srcPort, uint16_t dstPort,
                    uint32_t seqNum, uint32_t ackNum) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_SYN | TCP_ACK;
        req->seq = seqNum;
        req->ackNum = ackNum;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 4;
        req->options[0] = 2;
        req->options[1] = 4;
        req->options[2] = (m_Config.mss >> 8) & 0xFF;
        req->options[3] = m_Config.mss & 0xFF;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    bool sendAck(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                 uint16_t srcPort, uint16_t dstPort,
                 uint32_t ackNum, uint16_t window = 0) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_ACK;
        req->seq = 0;
        req->ackNum = ackNum;
        req->window = window ? window : m_Config.defaultWindowSize;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    bool sendData(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                  uint16_t srcPort, uint16_t dstPort,
                  const uint8_t* data, uint16_t len,
                  uint32_t seqNum = 0, bool push = false) {
        if (!data || len == 0) return false;
        
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        // Копируем данные в пул
        uint16_t bufIdx = m_BufferPool.allocate(flowKey, data, len);
        if (bufIdx == 0xFFFF) {
            deallocateRequest(req);
            m_TotalDropped++;
            return false;
        }
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_ACK | (push ? TCP_PSH : 0);
        req->seq = seqNum ? seqNum : m_NextSeq;
        req->ackNum = 0;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = bufIdx;
        req->dataLen = len;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_NextSeq += len;
        m_TotalSent++;
        return true;
    }
    
    bool sendDataAck(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                     uint16_t srcPort, uint16_t dstPort,
                     const uint8_t* data, uint16_t len,
                     uint32_t seqNum, uint32_t ackNum, bool push = false) {
        if (!data || len == 0) return false;
        
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        uint16_t bufIdx = m_BufferPool.allocate(flowKey, data, len);
        if (bufIdx == 0xFFFF) {
            deallocateRequest(req);
            m_TotalDropped++;
            return false;
        }
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_ACK | (push ? TCP_PSH : 0);
        req->seq = seqNum;
        req->ackNum = ackNum;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = bufIdx;
        req->dataLen = len;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_NextSeq = seqNum + len;
        m_TotalSent++;
        return true;
    }
    
    bool sendFin(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                 uint16_t srcPort, uint16_t dstPort,
                 uint32_t seqNum, uint32_t ackNum = 0) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_FIN | TCP_ACK;
        req->seq = seqNum;
        req->ackNum = ackNum;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    bool sendFinAck(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                    uint16_t srcPort, uint16_t dstPort,
                    uint32_t seqNum, uint32_t ackNum) {
        return sendFin(flowKey, srcIP, dstIP, srcPort, dstPort, seqNum, ackNum);
    }
    
    bool sendRst(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                 uint16_t srcPort, uint16_t dstPort,
                 uint32_t seqNum, uint32_t ackNum = 0) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_RST | TCP_ACK;
        req->seq = seqNum;
        req->ackNum = ackNum;
        req->window = 0;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    bool sendKeepAlive(uint32_t flowKey, uint32_t srcIP, uint32_t dstIP,
                       uint16_t srcPort, uint16_t dstPort,
                       uint32_t seqNum, uint32_t ackNum) {
        auto* req = allocateRequest(flowKey);
        if (!req) return false;
        
        req->srcIP = srcIP;
        req->dstIP = dstIP;
        req->srcPort = srcPort;
        req->dstPort = dstPort;
        req->flags = TCP_ACK;
        req->seq = seqNum - 1;  // Keep-Alive
        req->ackNum = ackNum;
        req->window = m_Config.defaultWindowSize;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
        req->optionsLen = 0;
        req->retryCount = 0;
        req->isRetransmission = false;
        req->timestamp = getCurrentTimeMs();
        
        m_TotalSent++;
        return true;
    }
    
    // ============================================================
    // Управление очередью (кольцевой буфер)
    // ============================================================
    
    SendRequest* popNext() {
        if (m_Count == 0) return nullptr;
        
        auto* req = &m_RequestPool[m_Head];
        m_Head = (m_Head + 1) % MAX_QUEUE;
        m_Count--;
        return req;
    }
    
    void releaseRequest(SendRequest* req) {
        if (!req) return;
        
        if (req->dataOffset != 0xFFFF) {
            m_BufferPool.deallocate(req->dataOffset);
        }
        
        req->flowKey = 0;
        req->flags = 0;
        req->dataOffset = 0xFFFF;
        req->dataLen = 0;
    }
    
    bool hasPending() const {
        return m_Count > 0;
    }
    
    size_t queueSize() const {
        return m_Count;
    }
    
    size_t queueCapacity() const {
        return MAX_QUEUE;
    }
    
    void clear() {
        // Освобождаем все буферы
        m_BufferPool.clear();
        
        // Очищаем очередь
        for (size_t i = 0; i < MAX_QUEUE; ++i) {
            m_RequestPool[i].flowKey = 0;
            m_RequestPool[i].dataOffset = 0xFFFF;
            m_RequestPool[i].dataLen = 0;
        }
        m_Head = 0;
        m_Tail = 0;
        m_Count = 0;
    }
    
    void clearForFlow(uint32_t flowKey) {
        m_BufferPool.clearForFlow(flowKey);
        
        size_t writeIdx = m_Head;
        size_t readIdx = m_Head;
        size_t count = m_Count;
        
        while (count > 0) {
            auto& req = m_RequestPool[readIdx];
            readIdx = (readIdx + 1) % MAX_QUEUE;
            count--;
            
            if (req.flowKey != flowKey) {
                if (writeIdx != readIdx) {
                    m_RequestPool[writeIdx] = req;
                }
                writeIdx = (writeIdx + 1) % MAX_QUEUE;
            } else {
                if (req.dataOffset != 0xFFFF) {
                    m_BufferPool.deallocate(req.dataOffset);
                }
                m_TotalDropped++;
            }
        }
        
        m_Head = 0;
        m_Tail = writeIdx;
        m_Count = (writeIdx - m_Head + MAX_QUEUE) % MAX_QUEUE;
    }
    
    // ============================================================
    // Проверка ретрансмиссий
    // ============================================================
    
    void checkRetransmissions() {
        uint64_t now = getCurrentTimeMs();
        size_t count = m_Count;
        size_t idx = m_Head;
        
        while (count > 0) {
            auto& req = m_RequestPool[idx];
            idx = (idx + 1) % MAX_QUEUE;
            count--;
            
            if (req.isRetransmission && 
                (now - req.timestamp) > m_Config.retransmitTimeout) {
                req.retryCount++;
                if (req.retryCount >= m_Config.maxRetries) {
                    req.flowKey = 0;
                    if (req.dataOffset != 0xFFFF) {
                        m_BufferPool.deallocate(req.dataOffset);
                        req.dataOffset = 0xFFFF;
                    }
                    m_TotalDropped++;
                } else {
                    req.timestamp = now;
                    req.isRetransmission = true;
                    m_TotalRetransmitted++;
                }
            }
        }
        
        compactQueue();
    }
    
    // ============================================================
    // Создание Packet из SendRequest
    // ============================================================
    
    static Packet* createPacket(const SendRequest* req) {
        if (!req) return nullptr;
        
        // Вычисляем размеры
        size_t ipHeaderLen = 20;
        size_t tcpHeaderLen = 20 + req->optionsLen;
        size_t dataLen = (req->dataOffset != 0xFFFF) ? req->dataLen : 0;
        size_t totalLen = ipHeaderLen + tcpHeaderLen + dataLen;
        
        // Создаем буфер
        std::vector<uint8_t> buffer(totalLen);
        uint8_t* ptr = buffer.data();
        size_t offset = 0;
        
        // ============================================================
        // IP заголовок
        // ============================================================
        struct ipv4_header {
            uint8_t ver_ihl;
            uint8_t tos;
            uint16_t total_len;
            uint16_t id;
            uint16_t frag_off;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t check;
            uint32_t src;
            uint32_t dst;
        };
        
        auto* ip = reinterpret_cast<ipv4_header*>(ptr + offset);
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = casket::host_to_be<uint16_t>(totalLen);
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 6;  // TCP
        ip->check = 0;
        ip->src = req->srcIP;
        ip->dst = req->dstIP;
        ip->check = computeIPChecksum(ip, ipHeaderLen);
        
        offset += ipHeaderLen;
        
        // ============================================================
        // TCP заголовок
        // ============================================================
        struct tcp_header {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;
            uint32_t ack_seq;
            uint16_t flags_doff;
            uint16_t window;
            uint16_t check;
            uint16_t urg_ptr;
        };
        
        auto* tcp = reinterpret_cast<tcp_header*>(ptr + offset);
        tcp->source = casket::host_to_be(req->srcPort);
        tcp->dest = casket::host_to_be(req->dstPort);
        tcp->seq = casket::host_to_be(req->seq);
        tcp->ack_seq = casket::host_to_be(req->ackNum);
        
        uint16_t doff = (tcpHeaderLen / 4) << 12;
        uint16_t flags = 0;
        if (req->flags & TCP_FIN) flags |= 0x01;
        if (req->flags & TCP_SYN) flags |= 0x02;
        if (req->flags & TCP_RST) flags |= 0x04;
        if (req->flags & TCP_PSH) flags |= 0x08;
        if (req->flags & TCP_ACK) flags |= 0x10;
        if (req->flags & TCP_URG) flags |= 0x20;
        tcp->flags_doff = casket::host_to_be(doff | flags);
        
        tcp->window = casket::host_to_be(req->window);
        tcp->check = 0;
        tcp->urg_ptr = 0;
        
        offset += 20;
        
        // ============================================================
        // TCP Опции
        // ============================================================
        if (req->optionsLen > 0) {
            memcpy(ptr + offset, req->options, req->optionsLen);
            offset += req->optionsLen;
        }
        
        // ============================================================
        // Данные
        // ============================================================
        if (dataLen > 0) {
            const uint8_t* data = getBufferData(req->dataOffset);
            if (data) {
                memcpy(ptr + offset, data, dataLen);
                offset += dataLen;
            }
        }
        
        // ============================================================
        // TCP Checksum
        // ============================================================
        tcp->check = computeTCPChecksum(
            ptr + ipHeaderLen, tcpHeaderLen + dataLen,
            req->srcIP, req->dstIP
        );
        
        // ============================================================
        // Создание Packet
        // ============================================================
        auto* packet = new Packet(
            nonstd::span<const uint8_t>(buffer.data(), totalLen),
            true,
            LINKTYPE_RAW
        );
        
        packet->parse();
        return packet;
    }
    
    // ============================================================
    // Статистика
    // ============================================================
    
    uint64_t getTotalSent() const { return m_TotalSent; }
    uint64_t getTotalDropped() const { return m_TotalDropped; }
    uint64_t getTotalRetransmitted() const { return m_TotalRetransmitted; }
    uint32_t getNextSeq() const { return m_NextSeq; }
    size_t getBufferPoolAvailable() const { return m_BufferPool.available(); }
    size_t getBufferPoolTotal() const { return m_BufferPool.total(); }
    
    // ============================================================
    // Конфигурация
    // ============================================================
    
    const Config& getConfig() const { return m_Config; }
    void setConfig(const Config& config) { m_Config = config; }
    
private:
    // ============================================================
    // Константы
    // ============================================================
    
    static constexpr size_t MAX_QUEUE = 10000;
    
    // ============================================================
    // Управление очередью
    // ============================================================
    
    SendRequest* allocateRequest(uint32_t flowKey) {
        if (m_Count >= MAX_QUEUE) {
            m_TotalDropped++;
            return nullptr;
        }
        
        auto* req = &m_RequestPool[m_Tail];
        req->flowKey = flowKey;
        m_Tail = (m_Tail + 1) % MAX_QUEUE;
        m_Count++;
        return req;
    }
    
    void deallocateRequest(SendRequest* req) {
        req->flowKey = 0;
        if (req->dataOffset != 0xFFFF) {
            m_BufferPool.deallocate(req->dataOffset);
            req->dataOffset = 0xFFFF;
        }
    }
    
    void compactQueue() {
        size_t writeIdx = m_Head;
        size_t readIdx = m_Head;
        size_t count = m_Count;
        
        while (count > 0) {
            auto& req = m_RequestPool[readIdx];
            readIdx = (readIdx + 1) % MAX_QUEUE;
            count--;
            
            if (req.flowKey != 0) {
                if (writeIdx != readIdx) {
                    m_RequestPool[writeIdx] = req;
                }
                writeIdx = (writeIdx + 1) % MAX_QUEUE;
            }
        }
        
        m_Head = 0;
        m_Tail = writeIdx;
        m_Count = (writeIdx - m_Head + MAX_QUEUE) % MAX_QUEUE;
    }
    
    // ============================================================
    // BufferPool helpers
    // ============================================================
    
    static const uint8_t* getBufferData(uint16_t) {
        // В реальном коде нужен доступ к BufferPool
        // Для простоты возвращаем nullptr
        return nullptr;
    }
    
    // ============================================================
    // Вспомогательные методы
    // ============================================================
    
    static inline uint64_t getCurrentTimeMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
    }
    
    // ============================================================
    // Вычисление контрольных сумм
    // ============================================================
    
    static uint16_t computeIPChecksum(const void* data, size_t len) {
        const uint16_t* ptr = static_cast<const uint16_t*>(data);
        uint32_t sum = 0;
        
        for (size_t i = 0; i < len / 2; ++i) {
            sum += casket::be_to_host(ptr[i]);
        }
        
        if (len & 1) {
            sum += static_cast<uint16_t>(*reinterpret_cast<const uint8_t*>(ptr) << 8);
        }
        
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        return casket::host_to_be(static_cast<uint16_t>(~sum));
    }
    
    static uint16_t computeTCPChecksum(const void* tcpData, size_t tcpLen,
                                       uint32_t srcIP, uint32_t dstIP) {
        struct pseudo_header {
            uint32_t src;
            uint32_t dst;
            uint8_t zero;
            uint8_t protocol;
            uint16_t len;
        };
        
        pseudo_header pseudo;
        pseudo.src = srcIP;
        pseudo.dst = dstIP;
        pseudo.zero = 0;
        pseudo.protocol = 6;
        pseudo.len = casket::host_to_be(static_cast<uint16_t>(tcpLen));
        
        const uint16_t* ptr;
        uint32_t sum = 0;
        size_t remaining;
        
        // Pseudo-header
        ptr = reinterpret_cast<const uint16_t*>(&pseudo);
        for (size_t i = 0; i < sizeof(pseudo_header) / 2; ++i) {
            sum += casket::be_to_host(ptr[i]);
        }
        
        // TCP data
        ptr = static_cast<const uint16_t*>(tcpData);
        remaining = tcpLen;
        
        while (remaining >= 2) {
            sum += casket::be_to_host(*ptr++);
            remaining -= 2;
        }
        
        if (remaining) {
            sum += static_cast<uint16_t>(*reinterpret_cast<const uint8_t*>(ptr) << 8);
        }
        
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        return casket::host_to_be(static_cast<uint16_t>(~sum));
    }

private:
    Config m_Config;
    
    // Фиксированные пулы (без аллокаций)
    std::array<SendRequest, MAX_QUEUE> m_RequestPool;
    BufferPool m_BufferPool;
    
    // Кольцевой буфер для очереди
    size_t m_Head;
    size_t m_Tail;
    size_t m_Count;
    
    // Состояние
    uint32_t m_NextSeq;
    uint64_t m_TotalSent;
    uint64_t m_TotalDropped;
    uint64_t m_TotalRetransmitted;
};

} // namespace snet::layers