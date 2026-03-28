#pragma once
#include <snet/io.hpp>
#include <snet/layers/packet_pool.hpp>

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

    /// @brief Receives a single packet from the Netfilter queue
    /// @param[out] packet Pointer to receive the captured packet
    /// @return RecvStatus indicating result:
    ///         - OK: Packet successfully received
    ///         - WouldBlock: No packet available (non-blocking mode)
    ///         - Interrupted: Capture was interrupted
    ///         - Error: Error occurred during reception
    RecvStatus receivePacket(layers::Packet** packet) override;

    /// @brief Receives multiple packets in a single operation
    /// @param[out] packet Array of packet pointers to fill
    /// @param[in,out] packetCount On input, maximum number of packets;
    ///                             on output, actual number received
    /// @param[in] maxCount Maximum number of packets to receive
    /// @return RecvStatus indicating result
    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, 
                              uint16_t maxCount) override;

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
    struct Impl;                     ///< PIMPL forward declaration
    std::unique_ptr<Impl> impl_;     ///< Pointer to implementation details
};

} // namespace snet::driver