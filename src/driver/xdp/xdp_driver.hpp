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

    Status configure(const snet::io::Config& config) override;
    Status start() override;
    Status stop() override;
    Status interrupt() override;

    size_t deviceCount() const override;
    io::Device* deviceAt(size_t idx) const override;

    RecvStatus receivePackets(RxItem* rx, uint16_t* count, uint16_t max) override;
    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;
    Status transmitPacket(layers::Packet* packet, io::DeviceId egress) override;

    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;
    Status getStats(Stats* stats) override;
    void resetStats() override;
    snet::layers::LinkLayerType getDataLinkType() const override;

    // ---- shared UMEM pool (used by XdpInstance) ----
    uint64_t acquireFrame();
    void     releaseFrame(uint64_t addr);
    uint32_t freeFrameCount() const noexcept;

    uint32_t frameSize() const noexcept { return frameSize_; }
    uint32_t headroom()  const noexcept { return headroom_; }
    uint32_t compSize()  const noexcept { return compSize_; }
    void*    umemBase()  const noexcept { return umemArea_; }

private:
    struct Endpoint
    {
        std::string iface;
        uint32_t queue{0};
    };

    struct IfaceContext
    {
        std::string iface;
        uint32_t ifindex{0};
        std::vector<XdpInstance*> instances;
    };

    Status parseEndpoints(const std::string& input);
    bool setupRlimit();
    bool createUmem();
    void destroyUmem() noexcept;
    void clearAll();

    // --- config ---
    std::vector<Endpoint> endpoints_;
    bool zeroCopy_{true};
    bool needWakeup_{true};
    uint32_t numFrames_{xdp::kDefaultNumFrames};
    uint32_t frameSize_{xdp::kDefaultFrameSize};
    uint32_t headroom_{xdp::kDefaultHeadroom};
    uint32_t fillSize_{xdp::kDefaultFillSize};
    uint32_t compSize_{xdp::kDefaultCompSize};
    uint32_t rxSize_{xdp::kDefaultRxSize};
    uint32_t txSize_{xdp::kDefaultTxSize};
    uint32_t batchSize_{xdp::kDefaultBatchSize};
    int32_t timeoutMs_{-1};

    // --- UMEM ---
    void* umemArea_{nullptr};
    size_t umemAreaSize_{0};
    struct xsk_umem* umem_{nullptr};
    struct xsk_ring_prod umemFq_{};
    struct xsk_ring_cons umemCq_{};

    // --- frame pool ---
    std::vector<uint64_t> freeFrames_;
    mutable std::mutex poolMutex_;

    // --- instances ---
    std::vector<std::unique_ptr<IfaceContext>> ifaces_;
    std::vector<XdpInstancePtr> instancesOwned_;
    std::vector<XdpInstance*> instances_;
    XdpPoolPtr pool_;
    size_t currInstanceIdx_{0};

    std::atomic<bool> interrupted_{false};
    Stats stats_{};
};

} // namespace snet::driver