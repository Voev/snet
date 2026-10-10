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
    Pairs,   ///< 0<->1, 2<->3, ... (default)
    Ring,    ///< 0->1->...->N-1->0
    Single,  ///< each endpoint forwards to itself
};

class XdpDriver final : public snet::io::DriverBase
{
public:
    using XdpPool         = casket::FixedObjectPool<XdpWrapper>;
    using XdpPoolPtr      = std::unique_ptr<XdpPool>;
    using XdpInstancePtr  = std::unique_ptr<XdpInstance>;

    explicit XdpDriver(const io::DriverSpec& config);
    ~XdpDriver() noexcept override;

    static std::shared_ptr<io::Driver> create(const io::DriverSpec& config);

    const char* getName() const override;

    Status declareOptions(io::Config& config) override;
    Status configure(const snet::io::Config& config) override;
    Status start() override;
    Status stop() override;
    Status interrupt() override;

    Status inject(const uint8_t* data, uint32_t dataLen) override;

    Status getStats(Stats* stats) override;
    void   resetStats() override;

    int getSnaplen() const override;
    snet::layers::LinkLayerType getDataLinkType() const override;

    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;
    Status     finalizePacket(layers::Packet* rawPacket, Verdict verdict) override;

    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

private:
    /// One endpoint as parsed from the input string.
    struct Endpoint
    {
        std::string iface;
        uint32_t    queue{0};
    };

    /// Per-iface BPF program + XSKMAP + the instances bound to it.
    struct IfaceContext
    {
        std::string            iface;
        uint32_t               ifindex{0};
        struct xdp_program*    program{nullptr};
        int                    xskmapFd{-1};
        std::vector<XdpInstance*> instances;   ///< non-owning, see instancesOwned_
    };

    Status parseEndpoints(const std::string& input);
    Status parseTopology();

    bool   setupRlimit();
    bool   createUmem();
    void   destroyUmem() noexcept;
    bool   openBpfForIface(IfaceContext& ctx);
    void   closeBpfForIface(IfaceContext& ctx) noexcept;
    void   buildPeers();
    void   clearAll();

    uint32_t refillFq(XdpInstance& inst, uint32_t max);
    uint32_t processCq(XdpInstance& inst, uint32_t max);
    bool     kickTx(XdpInstance& inst);

    uint64_t acquireFrame();
    void     releaseFrame(uint64_t addr);

    bool transmitFrame(XdpInstance* egress, uint64_t frameAddr, uint32_t len);
    void swapMacInPlace(uint64_t frameAddr, uint32_t len) noexcept;

private:
    std::string           endpointsStr_;
    std::vector<Endpoint> endpoints_;

    std::string           bpfObject_;
    std::string           bpfSection_{"xdp"};
    bool                  zeroCopy_{true};
    bool                  needWakeup_{true};

    uint32_t              numFrames_{xdp::kDefaultNumFrames};
    uint32_t              frameSize_{xdp::kDefaultFrameSize};
    uint32_t              headroom_{xdp::kDefaultHeadroom};
    uint32_t              fillSize_{xdp::kDefaultFillSize};
    uint32_t              compSize_{xdp::kDefaultCompSize};
    uint32_t              rxSize_{xdp::kDefaultRxSize};
    uint32_t              txSize_{xdp::kDefaultTxSize};
    uint32_t              batchSize_{xdp::kDefaultBatchSize};

    size_t                snaplen_{xdp::kDefaultFrameSize};
    int32_t               timeoutMs_{-1};

    std::string           topologyStr_{"pairs"};
    ForwardTopology       topology_{ForwardTopology::Pairs};

    bool                  swapMac_{false};

    void*                 umemArea_{nullptr};
    size_t                umemAreaSize_{0};
    struct xsk_umem*      umem_{nullptr};
    struct xsk_ring_prod  umemFq_{};        ///< dummy, required by API
    struct xsk_ring_cons  umemCq_{};        ///< dummy, required by API

    std::vector<uint64_t> freeFrames_;
    std::mutex            poolMutex_;

    std::vector<std::unique_ptr<IfaceContext>> ifaces_;

    std::vector<XdpInstancePtr> instancesOwned_;  ///< owning
    std::vector<XdpInstance*>   instances_;       ///< flat, non-owning view

    XdpPoolPtr            pool_;

    size_t                currInstanceIdx_{0};
    std::atomic<bool>     interrupted_{false};
    Stats                 stats_{};
    uint64_t              packetsSentCounter_{0};
};

} // namespace snet::driver