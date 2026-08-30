#pragma once
#include <cstdint>
#include <functional>
#include <vector>
#include <snet/layers/l4/tcp_types.hpp>

namespace snet::layers
{

/// @brief Sends TCP data with proper SEQ/ACK management.
class TcpSender
{
public:
    using SendCallback = std::function<void(const uint8_t* data, size_t len)>;

    TcpSender(SendCallback send_callback, uint32_t initial_seq = 0x100000, uint32_t initial_ack = 0)
        : send_callback_(std::move(send_callback))
        , seq_(initial_seq)
        , ack_(initial_ack)
    {
    }

    /// @brief Send data to the other side.
    void send(const uint8_t* data, size_t len, bool push = true)
    {
        if (!send_callback_ || len == 0)
            return;
        send_callback_(data, len);
        seq_ += len;
    }

    /// @brief Send data from StreamData.
    void send(const StreamData& data)
    {
        send(data.data, data.len);
    }

    /// @brief Send ACK packet.
    void sendAck()
    {
        send_callback_(nullptr, 0);
    }

    /// @brief Send FIN packet.
    void sendFin()
    {
        send_callback_(nullptr, 0);
        seq_ += 1;
    }

    /// @brief Send RST packet.
    void sendRst()
    {
        send_callback_(nullptr, 0);
    }

    /// @brief Update ACK number.
    void updateAck(uint32_t ack)
    {
        ack_ = ack;
    }

    /// @brief Update SEQ number.
    void updateSeq(uint32_t seq)
    {
        seq_ = seq;
    }

    uint32_t getSeq() const
    {
        return seq_;
    }
    uint32_t getAck() const
    {
        return ack_;
    }

private:
    SendCallback send_callback_;
    uint32_t seq_;
    uint32_t ack_;
};

} // namespace snet::layers