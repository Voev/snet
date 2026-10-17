#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <snet/io.hpp>
#include <snet/io/driver_base.hpp>

#include <casket/types/fixed_object_pool.hpp>

#include "xdp_types.hpp"
#include "xdp_wrapper.hpp"
#include "xdp_instance.hpp"

#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>

struct xsk_umem;
struct xdp_program;

namespace snet::driver
{

/// @brief XDP driver implementation using AF_XDP.
/// @details Manages multiple XdpInstance objects, UMEM, BPF programs, and packet forwarding.
class XdpDriver final : public snet::io::DriverBase
{
public:
    using XdpPool = casket::FixedObjectPool<XdpWrapper>; ///< Pool type for XdpWrapper.
    using XdpPoolPtr = std::unique_ptr<XdpPool>;         ///< Unique pointer to pool.
    using XdpInstancePtr = std::unique_ptr<XdpInstance>; ///< Unique pointer to instance.

    /// @brief Constructs the driver with the given specification.
    /// @param[in] config Driver specification.
    explicit XdpDriver(const io::DriverSpec& config);

    /// @brief Destroys the driver and releases resources.
    ~XdpDriver() noexcept override;

    /// @brief Creates a shared pointer to an XdpDriver.
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

    /// @brief Applies configuration settings to the driver.
    /// @param[in] config Configuration source.
    /// @return Status of the operation.
    Status configure(const snet::io::Config& config) override;

    /// @brief Starts the driver and initializes all instances.
    /// @return Status of the operation.
    Status start() override;

    /// @brief Stops the driver and tears down all instances.
    /// @return Status of the operation.
    Status stop() override;

    /// @brief Signals the driver to interrupt pending operations.
    /// @return Status of the operation.
    Status interrupt() override;

    /// @brief Returns the number of registered devices.
    /// @return Device count.
    size_t deviceCount() const override;

    /// @brief Returns the device at the given index.
    /// @param[in] idx Device index.
    /// @return Pointer to the device, or nullptr if out of range.
    io::Device* deviceAt(size_t idx) const override;

    /// @brief Receives packets from the RX rings.
    /// @param[out] rx Array of RX items to fill.
    /// @param[out] count Number of packets actually received.
    /// @param[in] max Maximum number of packets to receive.
    /// @return Receive status.
    RecvStatus receivePackets(RxItem* rx, uint16_t* count, uint16_t max) override;

    /// @brief Finalizes a packet after processing.
    /// @param[in] packet Packet to finalize.
    /// @param[in] verdict Verdict applied to the packet.
    /// @return Status of the operation.
    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    /// @brief Transmits a packet through the given egress device.
    /// @param[in] packet Packet to transmit.
    /// @param[in] egress Egress device identifier.
    /// @return Status of the operation.
    Status transmitPacket(layers::Packet* packet, io::DeviceId egress) override;

    /// @brief Retrieves packet pool information.
    /// @param[out] info Structure to fill with pool information.
    /// @return Status of the operation.
    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

    /// @brief Retrieves driver statistics.
    /// @param[out] stats Structure to fill with statistics.
    /// @return Status of the operation.
    Status getStats(Stats* stats) override;

    /// @brief Resets all driver statistics to zero.
    void resetStats() override;

    /// @brief Returns the data link layer type of the driver.
    /// @return Link layer type.
    snet::layers::LinkLayerType getDataLinkType() const override;

    /// @brief Acquires a free frame from the UMEM pool.
    /// @return Frame address, or invalid address if none available.
    uint64_t acquireFrame();

    /// @brief Releases a frame back to the UMEM pool.
    /// @param[in] addr Frame address to release.
    void releaseFrame(uint64_t addr);

    /// @brief Returns the number of free frames in the pool.
    /// @return Free frame count.
    uint32_t freeFrameCount() const noexcept;

    /// @brief Returns the configured frame size.
    /// @return Frame size in bytes.
    uint32_t frameSize() const noexcept
    {
        return frameSize_;
    }

    /// @brief Returns the configured headroom size.
    /// @return Headroom size in bytes.
    uint32_t headroom() const noexcept
    {
        return headroom_;
    }

    /// @brief Returns the configured completion ring size.
    /// @return Completion ring size.
    uint32_t compSize() const noexcept
    {
        return compSize_;
    }

    /// @brief Returns the base address of the UMEM area.
    /// @return Pointer to the UMEM memory region.
    void* umemBase() const noexcept
    {
        return umemArea_;
    }

private:
    /// @brief Endpoint descriptor (interface and queue).
    struct Endpoint
    {
        std::string iface; ///< Network interface name.
        uint32_t queue{0}; ///< Queue identifier.
    };

    /// @brief Per-interface runtime context.
    struct IfaceContext
    {
        std::string iface;                   ///< Network interface name.
        uint32_t ifindex{0};                 ///< Interface index.
        std::vector<XdpInstance*> instances; ///< Instances bound to this interface.
    };

    /// @brief Parses endpoint specification string into endpoints_.
    /// @param[in] input Endpoint specification string.
    /// @return Status of the operation.
    Status parseEndpoints(const std::string& input);

    /// @brief Configures RLIMIT_MEMLOCK for UMEM allocation.
    /// @return True on success, false otherwise.
    bool setupRlimit();

    /// @brief Creates the UMEM and associated rings.
    /// @return True on success, false otherwise.
    bool createUmem();

    /// @brief Destroys the UMEM and releases associated resources.
    void destroyUmem() noexcept;

    /// @brief Clears all internal state and releases resources.
    void clearAll();

private:
    std::vector<Endpoint> endpoints_;                   ///< Configured endpoints.
    bool zeroCopy_{true};                               ///< Whether zero-copy mode is enabled.
    bool needWakeup_{true};                             ///< Whether wakeup syscalls are needed.
    uint32_t numFrames_{xdp::kDefaultNumFrames};        ///< Number of UMEM frames.
    uint32_t frameSize_{xdp::kDefaultFrameSize};        ///< Size of each frame in bytes.
    uint32_t headroom_{xdp::kDefaultHeadroom};          ///< Headroom reserved per frame.
    uint32_t fillSize_{xdp::kDefaultFillSize};          ///< Fill ring size.
    uint32_t compSize_{xdp::kDefaultCompSize};          ///< Completion ring size.
    uint32_t rxSize_{xdp::kDefaultRxSize};              ///< RX ring size.
    uint32_t txSize_{xdp::kDefaultTxSize};              ///< TX ring size.
    uint32_t batchSize_{xdp::kDefaultBatchSize};        ///< Batch processing size.
    int32_t timeoutMs_{-1};                             ///< Poll timeout in milliseconds.
    void* umemArea_{nullptr};                           ///< Base address of UMEM memory region.
    size_t umemAreaSize_{0};                            ///< Size of UMEM memory region.
    struct xsk_umem* umem_{nullptr};                    ///< UMEM handle.
    struct xsk_ring_prod umemFq_{};                     ///< Fill ring producer.
    struct xsk_ring_cons umemCq_{};                     ///< Completion ring consumer.
    std::vector<uint64_t> freeFrames_;                  ///< Stack of free frame addresses.
    std::vector<std::unique_ptr<IfaceContext>> ifaces_; ///< Per-interface contexts.
    std::vector<XdpInstancePtr> instancesOwned_;        ///< Owned XDP instances.
    std::vector<XdpInstance*> instances_;               ///< Raw pointers to active instances.
    XdpPoolPtr pool_;                                   ///< Pool of XdpWrapper objects.
    size_t currInstanceIdx_{0};                         ///< Current instance index for round-robin.
    std::atomic<bool> interrupted_{false};              ///< Interrupt flag.
    Stats stats_{};                                     ///< Accumulated driver statistics.
};

} // namespace snet::driver