#pragma once
#include <snet/io.hpp>
#include <snet/layers/packet_pool.hpp>

#include "nfq_packet.hpp"

namespace snet::driver
{

/// @brief Netfilter queue driver for packet capture and injection
/// @details Implements packet I/O using Linux Netfilter framework.
///          Provides high-performance packet capture from iptables/nftables
///          queues with support for packet verdicts (ACCEPT, DROP, etc.).
/// @note Requires Linux kernel with Netfilter support and appropriate permissions
class NfQueue final : public io::Driver
{
public:
    /// @brief Constructs a Netfilter queue driver instance
    /// @param[in] config Driver configuration parameters (queue number, buffer size, etc.)
    explicit NfQueue(const io::DriverConfig& config);

    /// @brief Destructor, releases Netfilter queue resources
    ~NfQueue() noexcept;

    /// @brief Factory method for creating NfQueue driver instances
    /// @param[in] config Driver configuration parameters
    /// @return Shared pointer to created driver instance
    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    /// @brief Configures the driver with specified parameters
    /// @param[in] config Configuration parameters (queue number, copy mode, etc.)
    /// @return Status indicating success or failure
    Status configure(const io::Config& config) override;

    /// @brief Starts packet capture from the Netfilter queue
    /// @return Status indicating success or failure
    Status start() override;

    /// @brief Stops packet capture and closes the queue
    /// @return Status indicating success or failure
    Status stop() override;

    /// @brief Interrupts ongoing packet capture operations
    /// @details Causes blocking receive operations to return with RecvStatus::Interrupted
    /// @return Status indicating success or failure
    Status interrupt() override;

    /// @brief Receives multiple packets in a single operation
    /// @param[out] packet Array of packet pointers to fill
    /// @param[in,out] packetCount On input, maximum number of packets;
    ///                             on output, actual number received
    /// @param[in] maxCount Maximum number of packets to receive
    /// @return RecvStatus indicating result
    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;

    /// @brief Injects a raw packet through Netfilter
    /// @param[in] data Raw packet data buffer
    /// @param[in] data_len Length of the data buffer in bytes
    /// @return Status indicating success or failure
    Status inject(const uint8_t* data, uint32_t data_len) override;

    /// @brief Finalizes packet processing with verdict
    /// @param[in] packet Packet to finalize
    /// @param[in] verdict Processing decision (ACCEPT, DROP, STOLEN, etc.)
    /// @return Status indicating success or failure
    /// @note Must be called for each packet received via receivePacket/receivePackets
    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    /// @brief Gets the snapshot length (snaplen) for captured packets
    /// @return Maximum captured packet length in bytes
    int getSnaplen() const override;

    /// @brief Gets the link layer type of the capture source
    /// @return LinkLayerType enumeration value
    layers::LinkLayerType getDataLinkType() const override;

    /// @brief Retrieves packet pool statistics
    /// @param[out] info Structure to fill with pool information
    /// @return Status indicating success or failure
    Status getMsgPoolInfo(layers::PacketPoolInfo& info) override;

    /// @brief Gets the driver name
    /// @return Constant string containing driver identifier
    const char* getName() const override;

    /// @brief Gets current driver statistics
    /// @param[out] stats Structure to fill with statistics data
    /// @return Status indicating success or failure
    Status getStats(Stats* stats) override;

    /// @brief Resets all driver statistics counters to zero
    void resetStats() override;

private:
    /// Sends data through the socket.
    /// @param[in] buf Pointer to the data buffer.
    /// @param[in] len Size of the buffer in bytes.
    /// @param[out] ec Error code reference.
    /// @return Number of bytes sent, or -1 on error.
    ssize_t sendSocket(const void* buf, size_t len, std::error_code& ec) noexcept;

    /// Receives data from the socket.
    /// @param[out] buffer Pointer to the receive buffer.
    /// @param[in] bufferSize Size of the receive buffer in bytes.
    /// @param[in] blocking If true, waits for data; if false, non-blocking mode.
    /// @param[out] ec Error code reference.
    /// @return Number of bytes received, or -1 on error.
    ssize_t recvSocket(void* buffer, size_t bufferSize, bool blocking, std::error_code& ec) noexcept;

    /// Binds an address to the socket.
    /// @param[in] groups Bitmask of groups to bind.
    /// @param[in] pid Process ID (0 for any).
    /// @param[out] ec Error code reference.
    void bindAddress(unsigned int groups, pid_t pid, std::error_code& ec) noexcept;

    /// Closes the socket connection.
    void closeSocket() noexcept;

private:
    std::unique_ptr<layers::PacketPool<NfqPacket>> pool_; ///< Smart pointer to packet pool.
    Stats stats_;                                         ///< Statistics counters.
    uint8_t* buffer_;                                     ///< Pointer to I/O buffer.
    size_t bufferSize_;                                   ///< Buffer size in bytes.
    socket::SocketType socket_;                           ///< Socket type.
    sockaddr_nl address_;                                 ///< Netlink socket address.
    unsigned int queueNumber_;                            ///< Queue number.
    unsigned int queueMaxLength_;                         ///< Maximum queue length.
    unsigned int portid_;                                 ///< Port identifier.
    int snaplen_;                                         ///< Snapshot length.
    int timeout_;                                         ///< Timeout value.
    bool failOpen_;                                       ///< Fail-open flag.
    volatile bool interrupted_;                           ///< Interruption flag.
};

} // namespace snet::driver