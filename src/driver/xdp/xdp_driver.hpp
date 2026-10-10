#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include <snet/io.hpp>
#include <snet/io/driver_base.hpp>
#include <snet/layers/l2/mac_address.hpp>

#include <casket/types/fixed_object_pool.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>

#include "xdp_instance.hpp"
#include "xdp_wrapper.hpp"

namespace snet::driver
{

/// AF_XDP based driver for transparent TCP proxy.
///
/// The driver manages one or more network interfaces, each with its own
/// AF_XDP socket. All interfaces share a single UMEM so that frames can be
/// forwarded between interfaces without copying.
///
/// Interfaces are paired: a packet received on one interface is normally
/// forwarded through its peer. This is the standard transparent bridge
/// setup for inline proxies.
class XdpDriver final : public snet::io::DriverBase
{
public:
    using XdpPool = casket::FixedObjectPool<XdpWrapper>;
    using XdpPoolPtr = std::unique_ptr<XdpPool>;

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
    Status injectPacket(layers::Packet* rawPacket) override;

    Status getStats(Stats* stats) override;
    void resetStats() override;

    int getSnaplen() const override;
    snet::layers::LinkLayerType getDataLinkType() const override;

    RecvStatus receivePackets(layers::Packet** rawPacket, uint16_t* packetCount, uint16_t maxCount) override;
    Status finalizePacket(layers::Packet* rawPacket, Verdict verdict) override;

    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

private:
    // --- setup ---
    bool setupUmem(uint32_t numFrames, uint32_t frameSize);
    bool setupSocket(XdpInstance& inst, uint32_t queueId);
    bool loadXdpProgram(XdpInstance& inst);
    bool attachXdpProgram(XdpInstance& inst);
    void unloadXdpProgram(XdpInstance& inst) noexcept;

    // --- ring management ---
    void replenishFillRingFromCache() noexcept;
    void processCompletionRing() noexcept;
    uint64_t allocTxFrame() noexcept;
    void freeTxFrame(uint64_t frameAddr) noexcept;

    // --- forwarding ---
    bool forwardFrame(XdpInstance& egress, uint64_t frameAddr, uint32_t len) noexcept;
    bool transmitCopy(XdpInstance& egress, const uint8_t* data, uint32_t len) noexcept;

    XdpInstance* peerOf(const XdpInstance& inst) const noexcept;
    XdpInstance* findEgressByIp(uint32_t dstIp) const noexcept;

    // --- receive internals ---
    RecvStatus tryReceiveBurst(layers::Packet** rawPacket,
                               uint16_t* packetCount,
                               uint16_t maxCount) noexcept;
    void pollForEvents(int timeoutMs) noexcept;

    void cleanup() noexcept;

private:
    // --- config ---
    std::vector<std::string> devices_;
    uint32_t queueId_{0};
    uint32_t umemNumFrames_{8192};
    uint32_t umemFrameSize_{2048};
    uint32_t fillRingSize_{4096};
    uint32_t completionRingSize_{4096};
    uint32_t rxRingSize_{2048};
    uint32_t txRingSize_{2048};
    uint32_t batchSize_{64};
    bool zeroCopy_{false};        // VirtualBox: false (copy mode)
    bool useSkbMode_{true};       // VirtualBox: true (generic XDP)
    std::string bpfFilter_;
    std::string bpfObjPath_{"xdp_redirect.bpf.o"};

    // --- shared UMEM ---
    XdpUmemInfo umem_;

    // --- TX frame pool: reserved frames for inject path ---
    // Frames [0, txPoolSize_) are reserved exclusively for transmitCopy(),
    // so they are never handed out to the RX fill ring.
    std::vector<uint64_t> txFreeFrames_;
    uint32_t txPoolSize_{0};

    // --- runtime ---
    XdpPoolPtr pool_;
    std::atomic<bool> interrupted_{false};
    Stats stats_{};
    size_t snaplen_{0};

    std::vector<std::unique_ptr<XdpInstance>> instances_;
    size_t currInstanceIdx_{0};

    // Shared BPF program / map fds for the "one program for all ifaces" case.
    // The implementation below loads a separate bpf_object per interface,
    // so these are only used if you switch to single-program mode.
    struct bpf_object* sharedBpfObj_{nullptr};
    int sharedXskMapFd_{-1};
};

} // namespace snet::driver