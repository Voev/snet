#pragma once
#include <snet/io.hpp>
#include <snet/layers/packet_pool.hpp>

#include "pcap_handle.hpp"
#include "pcap_packet.hpp"

namespace snet::driver
{

/// @brief PCAP-based network driver implementation
/// @details Provides packet capture and injection capabilities using libpcap.
///          Supports both live capture from network interfaces and offline
///          processing of pcap files.
class Pcap final : public io::Driver
{
public:
    /// @brief Constructs a PCAP driver instance
    /// @param[in] config Driver configuration parameters
    explicit Pcap(const io::DriverConfig& config);

    /// @brief Destructor, releases PCAP resources
    ~Pcap() noexcept;

    /// @brief Factory method for creating PCAP driver instances
    /// @param[in] config Driver configuration parameters
    /// @return Shared pointer to created driver instance
    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    /// @brief Gets the driver name
    /// @return Constant string containing driver identifier
    const char* getName() const override;

    /// @brief Configures the driver with specified parameters
    /// @param[in] config Configuration parameters
    /// @return Status indicating success or failure
    Status configure(const io::Config& config) override;

    /// @brief Starts the packet capture process
    /// @return Status indicating success or failure
    Status start() override;

    /// @brief Stops the packet capture process
    /// @return Status indicating success or failure
    Status stop() override;

    /// @brief Interrupts ongoing packet capture operations
    /// @return Status indicating success or failure
    Status interrupt() override;

    /// @brief Receives a single packet from the capture source
    /// @param[out] packet Pointer to receive the captured packet
    /// @return RecvStatus indicating result (OK, WOULDBLOCK, INTERRUPTED, etc.)
    RecvStatus receivePacket(layers::Packet** packet) override;

    /// @brief Receives multiple packets in a single operation
    /// @param[out] packet Array of packet pointers to fill
    /// @param[in,out] packetCount On input, maximum number of packets;
    ///                             on output, actual number received
    /// @param[in] maxCount Maximum number of packets to receive
    /// @return RecvStatus indicating result
    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;

    /// @brief Finalizes packet processing and applies verdict
    /// @param[in] packet Packet to finalize
    /// @param[in] verdict Processing decision (DROP, ACCEPT, etc.)
    /// @return Status indicating success or failure
    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    /// @brief Injects a raw packet into the network
    /// @param[in] data Raw packet data buffer
    /// @param[in] dataLength Length of the data buffer in bytes
    /// @return Status indicating success or failure
    Status inject(const uint8_t* data, uint32_t dataLength) override;

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

    /// @brief Gets current driver statistics
    /// @param[out] stats Structure to fill with statistics data
    /// @return Status indicating success or failure
    Status getStats(Stats* stats) override;

    /// @brief Resets all driver statistics counters to zero
    void resetStats() override;

private:
    /// @brief Starts live capture from a network interface
    /// @return Status indicating success or failure
    Status startLive();

    /// @brief Starts offline processing from a pcap file
    /// @return Status indicating success or failure
    Status startOffline();

    /// @brief Applies BPF filter and completes setup
    /// @return Status indicating success or failure
    Status applyFilterAndFinish();

    /// @brief Sets non-blocking mode for the capture handle
    /// @param[in] nb true for non-blocking, false for blocking mode
    /// @return Status indicating success or failure
    Status setNonBlocking(bool nb);

    /// @brief Installs a BPF filter on the capture handle
    /// @param[in] filter Filter expression string
    /// @return Status indicating success or failure
    Status installFilter(const std::string& filter);

    /// @brief Updates hardware statistics from PCAP
    /// @return Status indicating success or failure
    Status updateHwStats() noexcept;

private:
    std::unique_ptr<layers::PacketPool<PcapPacket>> pool_; ///< Packet pool for memory management
    Stats stats_;                                          ///< Driver statistics counters
    char errbuf_[PCAP_ERRBUF_SIZE];                        ///< Error buffer for PCAP operations
    std::string device_;                                   ///< Network device name or file path
    std::string filter_;                                   ///< BPF filter expression
    PcapHandle handle_;                                    ///< PCAP handle wrapper
    FILE* fp_;                                             ///< File pointer for offline capture
    unsigned int snaplen_;                                 ///< Snapshot length in bytes
    int timeout_;                                          ///< Read timeout in milliseconds
    int bufferSize_;                                       ///< Buffer size for capture
    Mode mode_;                                            ///< Capture mode (LIVE or OFFLINE)
    uint32_t netmask_;                                     ///< Network mask for filter compilation
    uint32_t hwupdateCount_;                               ///< Hardware statistics update interval
    U32Counter recvCounter_;                               ///< Received packets counter
    U32Counter dropCounter_;                               ///< Dropped packets counter
    bool promiscMode_;                                     ///< Promiscuous mode flag
    bool immediateMode_;                                   ///< Immediate mode flag
    bool nonblocking_;                                     ///< Non-blocking mode flag
    volatile bool interrupted_;                            ///< Interruption flag for async operations
};

} // namespace snet::driver