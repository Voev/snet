// xdp_driver.hpp
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

namespace snet::driver
{

/// UMEM and fill/completion ring state shared between kernel and userspace.
struct XdpUmemInfo
{
    void* buffer{nullptr};
    struct xsk_ring_prod fill{};
    struct xsk_ring_cons comp{};
    struct xsk_umem* umem{nullptr};
    uint64_t frameSize{0};
    uint32_t numFrames{0};
};

/// Per-socket AF_XDP state (RX/TX rings and batching hints).
struct XdpSocketInfo
{
    struct xsk_ring_cons rx{};
    struct xsk_ring_prod tx{};
    struct xsk_socket* xsk{nullptr};
    struct xsk_ring_prod* fill{nullptr};
    struct xsk_ring_cons* comp{nullptr};
    uint32_t outstandingTx{0};
    uint32_t rxBatchSize{64};
    uint32_t txBatchSize{64};
};

/// AF_XDP based driver.
///
/// Unlike AF_PACKET, packets are redirected to userspace via XDP_REDIRECT
/// directly from the NIC driver, bypassing the kernel network stack. This
/// avoids traffic duplication: each packet is delivered exactly once.
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

private:
    /// Describes a single network interface bound to the driver.
    struct XdpInstance
    {
        std::string name;
        uint32_t ifindex{0};
        uint32_t ip{0};
        uint32_t netmask{0};
        layers::MacAddress mac;
    };

    bool setupUmem(uint32_t numFrames, uint32_t frameSize);
    bool setupSocket(const std::string& ifname, uint32_t queueId);
    bool loadXdpProgram(const std::string& ifname, int xskMapFd);

    bool refillFillRing(uint32_t count);
    bool processCompletionRing();

    RecvStatus waitForPacket();

    bool transmitPacket(const uint8_t* data, uint32_t len);
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

    XdpUmemInfo umem_;
    XdpSocketInfo socket_;
    int xskMapFd_{-1};
    int xdpProgFd_{-1};

    XdpPoolPtr pool_;
    std::atomic<bool> interrupted_{false};
    Stats stats_{};
    size_t snaplen_{0};

    std::vector<std::unique_ptr<XdpInstance>> instances_;
};

} // namespace snet::driver