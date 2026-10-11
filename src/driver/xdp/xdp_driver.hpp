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

/// @brief Forwarding topology between endpoints.
enum class ForwardTopology : uint8_t
{
    Pairs,  ///< 0<->1, 2<->3, ... (default)
    Ring,   ///< 0->1->...->N-1->0
    Single, ///< each endpoint forwards to itself
};

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

    /// @brief Returns the driver name.
    /// @return Driver name string.
    const char* getName() const override;

    /// @brief Declares configuration options.
    /// @param[in,out] config Configuration to declare options into.
    /// @return Status of the operation.
    Status declareOptions(io::Config& config) override;

    /// @brief Configures the driver from the given config.
    /// @param[in] config Configuration to apply.
    /// @return Status of the operation.
    Status configure(const snet::io::Config& config) override;

    /// @brief Starts the driver.
    /// @return Status of the operation.
    Status start() override;

    /// @brief Stops the driver.
    /// @return Status of the operation.
    Status stop() override;

    /// @brief Interrupts the driver.
    /// @return Status of the operation.
    Status interrupt() override;

    /// @brief Injects a packet into the driver.
    /// @param[in] data Pointer to packet data.
    /// @param[in] dataLen Length of packet data.
    /// @return Status of the operation.
    Status inject(const uint8_t* data, uint32_t dataLen) override;

    /// @brief Retrieves driver statistics.
    /// @param[out] stats Pointer to stats structure to fill.
    /// @return Status of the operation.
    Status getStats(Stats* stats) override;

    /// @brief Resets driver statistics.
    void resetStats() override;

    /// @brief Returns the snapshot length.
    /// @return Snapshot length.
    int getSnaplen() const override;

    /// @brief Returns the data link type.
    /// @return Data link type.
    snet::layers::LinkLayerType getDataLinkType() const override;

    /// @brief Receives packets.
    /// @param[out] packet Array of packet pointers to fill.
    /// @param[out] packetCount Number of packets received.
    /// @param[in] maxCount Maximum number of packets to receive.
    /// @return Receive status.
    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;

    /// @brief Finalizes a packet with a verdict.
    /// @param[in] rawPacket Packet to finalize.
    /// @param[in] verdict Verdict for the packet.
    /// @return Status of the operation.
    Status finalizePacket(layers::Packet* rawPacket, Verdict verdict) override;

    /// @brief Retrieves packet pool information.
    /// @param[out] info Packet pool info to fill.
    /// @return Status of the operation.
    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

private:
    /// @brief One endpoint as parsed from the input string.
    struct Endpoint
    {
        std::string iface; ///< Interface name.
        uint32_t queue{0}; ///< Queue ID.
    };

    /// @brief Per-iface BPF program + XSKMAP + the instances bound to it.
    struct IfaceContext
    {
        std::string iface;                          ///< Interface name.
        uint32_t ifindex{0};                        ///< Interface index.
        struct xdp_program* program{nullptr};       ///< BPF program handle.
        int xskmapFd{-1};                           ///< XSKMAP file descriptor.
        std::vector<XdpInstance*> instances;        ///< Non-owning instances (see instancesOwned_).
    };

    /// @brief Parses the endpoints string.
    /// @param[in] input Endpoints string.
    /// @return Status of the operation.
    Status parseEndpoints(const std::string& input);

    /// @brief Parses the topology string.
    /// @return Status of the operation.
    Status parseTopology();

    /// @brief Sets up RLIMIT_MEMLOCK.
    /// @return true on success, false otherwise.
    bool setupRlimit();

    /// @brief Creates the UMEM area.
    /// @return true on success, false otherwise.
    bool createUmem();

    /// @brief Destroys the UMEM area.
    void destroyUmem() noexcept;

    /// @brief Opens BPF for an interface context.
    /// @param[in,out] ctx Interface context.
    /// @return true on success, false otherwise.
    bool openBpfForIface(IfaceContext& ctx);

    /// @brief Closes BPF for an interface context.
    /// @param[in,out] ctx Interface context.
    void closeBpfForIface(IfaceContext& ctx) noexcept;

    /// @brief Builds peer relationships between instances.
    void buildPeers();

    /// @brief Clears all resources.
    void clearAll();

    /// @brief Refills the fill queue.
    /// @param[in] inst Instance to refill.
    /// @param[in] max Maximum number of frames to refill.
    /// @return Number of frames refilled.
    uint32_t refillFq(XdpInstance& inst, uint32_t max);

    /// @brief Processes the completion queue.
    /// @param[in] inst Instance to process.
    /// @param[in] max Maximum number of completions to process.
    /// @return Number of completions processed.
    uint32_t processCq(XdpInstance& inst, uint32_t max);

    /// @brief Kicks the TX ring.
    /// @param[in] inst Instance to kick.
    /// @return true on success, false otherwise.
    bool kickTx(XdpInstance& inst);

    /// @brief Acquires a free frame.
    /// @return Frame address, or 0 if none available.
    uint64_t acquireFrame();

    /// @brief Releases a frame back to the free list.
    /// @param[in] addr Frame address.
    void releaseFrame(uint64_t addr);

    /// @brief Transmits a frame to the egress instance.
    /// @param[in] egress Egress instance.
    /// @param[in] frameAddr Frame address.
    /// @param[in] len Frame length.
    /// @return true on success, false otherwise.
    bool transmitFrame(XdpInstance* egress, uint64_t frameAddr, uint32_t len);

    /// @brief Swaps MAC addresses in-place.
    /// @param[in] frameAddr Frame address.
    /// @param[in] len Frame length.
    void swapMacInPlace(uint64_t frameAddr, uint32_t len) noexcept;

private:
    std::string endpointsStr_;                      ///< Endpoints string.
    std::vector<Endpoint> endpoints_;               ///< Parsed endpoints.
    std::string bpfObject_;                         ///< BPF object file path.
    std::string bpfSection_{"xdp"};                 ///< BPF section name.
    bool zeroCopy_{true};                           ///< Zero-copy mode flag.
    bool needWakeup_{true};                         ///< Need wakeup flag.
    uint32_t numFrames_{xdp::kDefaultNumFrames};    ///< Number of frames.
    uint32_t frameSize_{xdp::kDefaultFrameSize};    ///< Frame size.
    uint32_t headroom_{xdp::kDefaultHeadroom};      ///< Headroom size.
    uint32_t fillSize_{xdp::kDefaultFillSize};      ///< Fill ring size.
    uint32_t compSize_{xdp::kDefaultCompSize};      ///< Completion ring size.
    uint32_t rxSize_{xdp::kDefaultRxSize};          ///< RX ring size.
    uint32_t txSize_{xdp::kDefaultTxSize};          ///< TX ring size.
    uint32_t batchSize_{xdp::kDefaultBatchSize};    ///< Batch size.
    size_t snaplen_{xdp::kDefaultFrameSize};        ///< Snapshot length.
    int32_t timeoutMs_{-1};                         ///< Timeout in milliseconds.
    std::string topologyStr_{"pairs"};              ///< Topology string.
    ForwardTopology topology_{ForwardTopology::Pairs}; ///< Forwarding topology.
    bool swapMac_{false};                           ///< Swap MAC flag.
    void* umemArea_{nullptr};                       ///< UMEM area pointer.
    size_t umemAreaSize_{0};                        ///< UMEM area size.
    struct xsk_umem* umem_{nullptr};                ///< UMEM handle.
    struct xsk_ring_prod umemFq_{};                 ///< Dummy FQ ring (required by API).
    struct xsk_ring_cons umemCq_{};                 ///< Dummy CQ ring (required by API).
    std::vector<uint64_t> freeFrames_;              ///< Free frame addresses.
    std::mutex poolMutex_;                          ///< Mutex for pool operations.
    std::vector<std::unique_ptr<IfaceContext>> ifaces_; ///< Interface contexts.
    std::vector<XdpInstancePtr> instancesOwned_;    ///< Owning instances.
    std::vector<XdpInstance*> instances_;           ///< Flat, non-owning view of instances.
    XdpPoolPtr pool_;                               ///< Packet wrapper pool.
    size_t currInstanceIdx_{0};                     ///< Current instance index for round-robin.
    std::atomic<bool> interrupted_{false};          ///< Interrupted flag.
    Stats stats_{};                                 ///< Driver statistics.
    uint64_t packetsSentCounter_{0};                ///< Packets sent counter.
};

} // namespace snet::driver