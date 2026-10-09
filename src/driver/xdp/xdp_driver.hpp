#pragma once

#include <memory>
#include <vector>
#include <atomic>
#include <string>

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
/// AF_XDP socket, XSK map and XDP program. All interfaces share a single
/// UMEM so frames can be forwarded between interfaces without copying.
///
/// Interfaces are paired: a packet received on one interface is normally
/// forwarded through its peer, which is the standard transparent bridge
/// setup for inline proxies.
class XdpDriver final : public snet::io::DriverBase
{
public:
    using XdpPool = casket::FixedObjectPool<XdpWrapper>;
    using XdpPoolPtr = std::unique_ptr<XdpPool>;

    explicit XdpDriver(const io::DriverSpec& config);
    ~XdpDriver() noexcept;

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

    /// Releases a UMEM frame back into the shared fill ring.
    void releaseFrame(uint64_t frameAddr) noexcept;

private:
    bool setupUmem(uint32_t numFrames, uint32_t frameSize);
    bool setupSocket(XdpInstance& inst, uint32_t queueId, bool isFirst);
    bool loadXdpProgram(XdpInstance& inst);
    bool attachXdpProgram(XdpInstance& inst);
    void unloadXdpProgram(XdpInstance& inst);
    bool insertXskIntoMap(XdpInstance& inst, uint32_t queueId);

    bool refillFillRing(uint32_t count);
    bool processCompletionRing();

    RecvStatus waitForPacket();

    bool transmitPacket(XdpInstance& inst, const uint8_t* data, uint32_t len);
    XdpInstance* findEgress(uint32_t dstIp) const noexcept;

    void cleanup();

private:
    std::vector<std::string> devices_;
    uint32_t queueId_{0};
    uint32_t umemNumFrames_{4096};
    uint32_t umemFrameSize_{2048};
    uint32_t fillRingSize_{2048};
    uint32_t completionRingSize_{2048};
    uint32_t rxRingSize_{2048};
    uint32_t txRingSize_{2048};
    uint32_t batchSize_{64};
    bool zeroCopy_{true};
    bool useSkbMode_{false};
    std::string bpfFilter_;
    std::string bpfObjPath_{"xdp_redirect.bpf.o"};

    /// Shared UMEM across all interfaces.
    XdpUmemInfo umem_;

    XdpPoolPtr pool_;
    std::atomic<bool> interrupted_{false};
    Stats stats_{};
    size_t snaplen_{0};

    std::vector<std::unique_ptr<XdpInstance>> instances_;
    size_t currInstanceIdx_{0};
};

} // namespace snet::driver