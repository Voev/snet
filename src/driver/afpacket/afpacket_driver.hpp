#pragma once

#include <memory>
#include <vector>
#include <atomic>

#include <snet/io.hpp>
#include <snet/io/driver_base.hpp>

#include <casket/types/fixed_object_pool.hpp>

#include "afpacket_types.hpp"
#include "afpacket_wrapper.hpp"
#include "afpacket_instance.hpp"
#include "afpacket_fanout.hpp"

#include <pcap.h>

namespace snet::driver
{

/// @brief AF_PACKET-based network driver implementation.
///
/// Uses Linux AF_PACKET sockets to capture and transmit packets,
/// optionally with packet fanout across multiple instances.
class AFPacketDriver final : public snet::io::DriverBase
{
public:
    /// @brief Pool of AF_PACKET wrapper objects.
    using AFPacketPool = casket::FixedObjectPool<AFPacketWrapper>;

    /// @brief Unique pointer to the AF_PACKET pool.
    using AFPacketPoolPtr = std::unique_ptr<AFPacketPool>;

    /// @brief Unique pointer to a single AF_PACKET instance.
    using AFPacketInstancePtr = std::unique_ptr<Instance>;

    /// @brief Constructs driver from specification.
    /// @param[in] config Driver specification.
    explicit AFPacketDriver(const io::DriverSpec& config);

    /// @brief Destructor.
    ~AFPacketDriver() noexcept;

    /// @brief Creates a shared instance of the driver.
    /// @param[in] config Driver specification.
    /// @return Shared pointer to the created driver.
    static std::shared_ptr<io::Driver> create(const io::DriverSpec& config);

    /// @brief Gets driver name.
    /// @return Driver identifier string.
    const char* getName() const override;

    /// @brief Registers driver-specific options in the config section.
    /// @param[out] config Shared driver configuration section.
    /// @return Status of the operation.
    Status declareOptions(io::Config& config) override;

    /// @brief Configures driver with specified parameters.
    /// @param[in] config Configuration parameters.
    /// @return Status indicating success or failure.
    Status configure(const snet::io::Config& config) override;

    /// @brief Starts driver operation.
    /// @return Status indicating success or failure.
    Status start() override;

    /// @brief Stops driver operation.
    /// @return Status indicating success or failure.
    Status stop() override;

    /// @brief Interrupts ongoing operations.
    /// @return Status indicating success or failure.
    Status interrupt() override;

    /// @brief Gets number of devices.
    /// @return Number of available devices.
    size_t deviceCount() const override;

    /// @brief Gets device by index.
    /// @param[in] idx Device index.
    /// @return Pointer to the device, or nullptr if idx is invalid.
    io::Device* deviceAt(size_t idx) const override;

    /// @brief Receives packets from the driver.
    /// @param[out] rx Array to fill with received packet items.
    /// @param[out] count Number of packets actually received.
    /// @param[in] max Maximum number of packets to receive.
    /// @return Receive status.
    RecvStatus receivePackets(io::Driver::RxItem* rx, uint16_t* count, uint16_t max) override;

    /// @brief Finalizes packet with verdict.
    /// @param[in] packet Packet to finalize.
    /// @param[in] verdict Processing decision.
    /// @return Status indicating success or failure.
    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    /// @brief Transmits a packet through the specified egress device.
    /// @param[in] packet Packet to transmit.
    /// @param[in] egress Egress device identifier.
    /// @return Status indicating success or failure.
    Status transmitPacket(layers::Packet* packet, io::DeviceId egress) override;

    /// @brief Gets packet pool information.
    /// @param[out] info Structure to fill with pool statistics.
    /// @return Status indicating success or failure.
    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

    /// @brief Gets driver statistics.
    /// @param[out] stats Structure to fill with statistics.
    /// @return Status indicating success or failure.
    Status getStats(Stats* stats) override;

    /// @brief Resets all statistics counters.
    void resetStats() override;

    /// @brief Gets link layer type.
    /// @return LinkLayerType enumeration value.
    snet::layers::LinkLayerType getDataLinkType() const override;

private:
    /// @brief Finds next available frame to receive from.
    /// @param[out] outInst Instance that produced the frame.
    /// @param[out] outFrame Received frame descriptor.
    /// @return True if a frame was found, false otherwise.
    bool findFrame(Instance*& outInst, Instance::RxFrame& outFrame);

    /// @brief Waits for an incoming packet on any instance.
    /// @return Receive status.
    RecvStatus waitForPacket();

    /// @brief Refreshes hardware statistics from the kernel.
    void updateHwStats();

    /// @brief Releases all outstanding RX frames back to the kernel.
    void releaseAllOutstandingFrames();

    /// @brief Applies the configured BPF filter to all instances.
    /// @return True on success, false otherwise.
    bool applyFilter();

private:
    std::vector<AFPacketInstancePtr> instances_; ///< Active AF_PACKET instances.
    AFPacketPoolPtr pool_;                       ///< Packet wrapper pool.
    std::string filter_;                         ///< BPF filter expression.
    struct bpf_program fcode_;                   ///< Compiled BPF program.
    size_t currInstanceIdx_{0};                  ///< Current round-robin instance index.
    std::atomic<bool> interrupted_{false};       ///< Interrupt flag for stopping loops.
    Stats stats_{};                              ///< Accumulated driver statistics.
    size_t snaplen_{0};                          ///< Capture snapshot length in bytes.

    std::vector<std::string> devices_; ///< Configured device names.
    uint32_t bufferSizeMb_{128};       ///< RX/TX ring buffer size in MiB.
    int32_t timeoutMs_{-1};            ///< Poll timeout in milliseconds (-1 = infinite).
    bool useTxRing_{false};            ///< Whether to use TX ring for transmission.

    afpacket::Fanout::Type fanoutType_{afpacket::Fanout::Type::Hash};    ///< Fanout hashing mode.
    afpacket::Fanout::Flags fanoutFlags_{afpacket::Fanout::Flags::None}; ///< Fanout behavior flags.
    bool fanoutEnabled_ = false;                                         ///< Whether packet fanout is enabled.
};

} // namespace snet::driver