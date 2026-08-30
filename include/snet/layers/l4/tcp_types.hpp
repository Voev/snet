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

// ============================================================================
// 2. TCP специфичные типы
// ============================================================================

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

// ============================================================================
// 3. Потоковые данные (для TcpStreamData)
// ============================================================================

/// @brief Piece of TCP stream data.
struct StreamData
{
    const uint8_t* data{nullptr};
    size_t len{0};
    size_t missing_bytes{0};
    ConnectionTuple tuple;
    std::chrono::time_point<std::chrono::high_resolution_clock> timestamp;

    StreamData() = default;

    StreamData(const uint8_t* d, size_t l, size_t missing, const ConnectionTuple& t,
               std::chrono::time_point<std::chrono::high_resolution_clock> ts)
        : data(d)
        , len(l)
        , missing_bytes(missing)
        , tuple(t)
        , timestamp(ts)
    {
    }

    bool hasData() const
    {
        return data != nullptr && len > 0;
    }
    bool hasMissingBytes() const
    {
        return missing_bytes > 0;
    }
    timeval getTimeVal() const;
};


/// @brief Complete connection information.
struct ConnectionInfo
{
    ConnectionTuple tuple;
    TCPState state{TCPState::SynSent};
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;
    std::chrono::time_point<std::chrono::high_resolution_clock> end_time;
    uint32_t client_seq{0};
    uint32_t server_seq{0};
    uint32_t client_ack{0};
    uint32_t server_ack{0};
    uint32_t client_seq_delta{0};
    uint32_t server_seq_delta{0};
    bool closed{false};

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
    uint32_t getFlowKey() const
    {
        return tuple.flowKey;
    }
};

} // namespace snet::layers