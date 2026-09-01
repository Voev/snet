#pragma once
#include <cstdint>
#include <chrono>
#include <sys/time.h>
#include <snet/layers/l3/ip_address.hpp>

namespace snet::layers
{

struct Endpoint
{
    IPAddress ip;
    uint16_t port;

    Endpoint()
        : port(0)
    {
    }
    Endpoint(const IPAddress& ip, uint16_t port)
        : ip(ip)
        , port(port)
    {
    }

    bool operator==(const Endpoint& other) const
    {
        return ip == other.ip && port == other.port;
    }

    bool operator!=(const Endpoint& other) const
    {
        return !(*this == other);
    }

    std::string toString() const
    {
        return ip.toString() + ":" + std::to_string(port);
    }
};

/// @brief TCP connection 5-tuple.
struct ConnectionTuple
{
    Endpoint client;
    Endpoint server;
    uint32_t flowKey{0};

    ConnectionTuple() = default;
    ConnectionTuple(const Endpoint& client, const Endpoint& server)
        : client(client)
        , server(server)
    {
        flowKey = makeFlowKey();
    }

    bool operator==(const ConnectionTuple& other) const
    {
        return flowKey == other.flowKey;
    }

    bool operator!=(const ConnectionTuple& other) const
    {
        return !(*this == other);
    }

private:
    uint32_t makeFlowKey() const
    {
        // Простой хеш: XOR адресов и портов
        uint32_t key = client.ip.toIPv4().toHost() ^ server.ip.toIPv4().toHost();
        key ^= (static_cast<uint32_t>(client.port) << 16) | server.port;
        return key;
    }
};

/// @brief TCP connection state.
enum class TCPState : uint8_t
{
    SynSent,     // SYN sent, waiting for SYN-ACK
    SynReceived, // SYN-ACK received
    Established, // Connection established
    FinWait1,    // FIN sent, waiting for ACK
    FinWait2,    // ACK received for FIN, waiting for FIN
    Closing,     // Both sides FIN
    TimeWait,    // Waiting for timeout
    Closed       // Connection closed
};

/**
 * An enum for connection end reasons
 */
enum ConnectionEndReason
{
    /** Connection ended because of FIN or RST packet */
    TcpReassemblyConnectionClosedByFIN_RST,
    /** Connection ended manually by the user */
    TcpReassemblyConnectionClosedManually
};

/// @brief TCP flags (bitmask).
enum TCPFlags : uint8_t
{
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20,
    TCP_ECE = 0x40,
    TCP_CWR = 0x80
};

/// @brief TCP flow direction.
enum class Direction : uint8_t
{
    ClientToServer,
    ServerToClient
};

/// @brief Zero-copy TCP fragment.
struct TcpFragment
{
    uint32_t sequence{0};
    size_t dataLength{0};
    std::unique_ptr<uint8_t[]> data;
    std::chrono::time_point<std::chrono::high_resolution_clock> timestamp;

    TcpFragment() = default;

    TcpFragment(uint32_t seq, size_t len, uint8_t* d)
        : sequence(seq)
        , dataLength(len)
        , data(d) // ← захват владения без копирования
    {
    }

    TcpFragment(uint32_t seq, const uint8_t* d, size_t len)
        : sequence(seq)
        , dataLength(len)
        , data(new uint8_t[len])
    {
        std::memcpy(data.get(), d, len);
    }

    TcpFragment(TcpFragment&& other) noexcept
        : sequence(other.sequence)
        , dataLength(other.dataLength)
        , data(std::move(other.data))
        , timestamp(other.timestamp)
    {
        other.dataLength = 0;
    }

    TcpFragment& operator=(TcpFragment&& other) noexcept
    {
        if (this != &other)
        {
            sequence = other.sequence;
            dataLength = other.dataLength;
            data = std::move(other.data);
            timestamp = other.timestamp;
            other.dataLength = 0;
        }
        return *this;
    }

    TcpFragment(const TcpFragment&) = delete;
    TcpFragment& operator=(const TcpFragment&) = delete;

    bool hasData() const
    {
        return data != nullptr && dataLength > 0;
    }
    uint32_t endSequence() const
    {
        return sequence + static_cast<uint32_t>(dataLength);
    }
    const uint8_t* getData() const
    {
        return data.get();
    }
    uint8_t* getData()
    {
        return data.get();
    }

    /// @brief Отдать владение данными (zero-copy).
    uint8_t* releaseData()
    {
        return data.release();
    }
};

struct ConnectionInfo
{
    ConnectionTuple tuple;
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;
    std::chrono::time_point<std::chrono::high_resolution_clock> end_time;

    ConnectionInfo() = default;
    ConnectionInfo(const ConnectionTuple& t)
        : tuple(t)
    {
    }

    uint32_t getFlowKey() const
    {
        return tuple.flowKey;
    }
    IPAddress getClientIP() const
    {
        return tuple.client.ip;
    }
    uint16_t getClientPort() const
    {
        return tuple.client.port;
    }
    IPAddress getServerIP() const
    {
        return tuple.server.ip;
    }
    uint16_t getServerPort() const
    {
        return tuple.server.port;
    }
};

} // namespace snet::layers