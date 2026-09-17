#pragma once

#include <memory>
#include <vector>
#include <atomic>

#include <snet/io.hpp>

#include <casket/types/fixed_object_pool.hpp>

#include "afpacket_types.hpp"
#include "afpacket_config.hpp"
#include "afpacket_wrapper.hpp"
#include "afpacket_instance.hpp"

namespace snet::driver
{

class AFPacketDriver final : public snet::io::Driver
{
public:
    using AFPacketPool = casket::FixedObjectPool<AFPacketWrapper>;
    using AFPacketPoolPtr = std::unqiue_ptr<AFPacketPool>;
    using AFPacketInstancePtr = std::unique_ptr<Instance>;

    AFPacketDriver();
    ~AFPacketDriver() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    const char* getName() const override;

    Status configure(const snet::io::Config& config) override;
    Status start() override;
    Status stop() override;
    Status interrupt() override;

    Status inject(const uint8_t* data, uint32_t dataLen) override;

    Status getStats(Stats* stats) override;

    void resetStats() override;

    int getSnaplen() const override;
    snet::layers::LinkLayerType getDataLinkType() const override;

    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;

    Status finalizePacket(layers::Packet* rawPacket, Verdict verdict) override;

    Status getMsgPoolInfo(snet::io::PacketPoolInfo& info) override;

private:
    bool configureFanout(Instance& inst);
    bool startInstance(Instance& inst);

    bool calculateFrameSize(Instance& inst);
    bool calculateLayout(Instance& inst, tpacket_req& layout, int order);
    bool mmapRings(Instance& inst);
    bool setupRing(Ring& ring);

    void updateHwStats();
    bool transmitPacket(Instance* egress, const uint8_t* data, uint32_t len);

    RingEntry* findPacket();
    RecvStatus waitForPacket();
    void releaseAllOutstandingFrames();

private:
    AFPacketConfig cfg_;
    std::vector<AFPacketInstancePtr> instances_;
    AFPacketPoolPtr pool_;
    size_t currInstanceIdx_{0};
    std::atomic<bool> interrupted_{false};
    Stats stats_{};
    int snaplen_{0};
};

} // namespace snet::driver