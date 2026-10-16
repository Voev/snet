#pragma once

#include <snet/io.hpp>
#include <snet/pp/packet_pipeline.hpp>
#include <snet/arp/arp_resolver.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/l2/eth_header.hpp>

namespace snet::pp
{

class ForwardingStage final : public IPacketStage
{
public:
    ForwardingStage(io::Driver& driver, arp::ArpResolver& arp)
        : driver_(driver)
        , arp_(arp)
    {
    }

    const char* name() const noexcept override
    {
        return "ForwardingStage";
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        if (ctx.egress == io::kInvalidDevice)
            return StageResult::Continue;

        io::Device* device = io::FindDeviceById(driver_, ctx.egress);
        if (!device)
        {
            return StageResult::Drop;
        }

        auto dstMac = arp_.lookup(ctx.egress, ctx.nextHopIp);
        if (!dstMac)
        {
            arp_.request(ctx.egress, ctx.nextHopIp);
            return StageResult::Pending;
        }

        if (!rewriteMac(pkt, device->mac(), *dstMac))
            return StageResult::Drop;

        driver_.transmitPacket(pkt, ctx.egress);
        return StageResult::Consumed;
    }

    StageResult resume(layers::Packet* pkt, PacketContext& ctx) override
    {
        return process(pkt, ctx);
    }

    void tick() override
    {
        arp_.tick();
    }

private:
    static bool rewriteMac(layers::Packet* pkt, const layers::MacAddress& srcMac, const layers::MacAddress& dstMac)
    {
        using namespace snet::layers;

        auto* eth = pkt->findLayer(layers::Ethernet);
        if (!eth)
            return false;

        auto* raw = reinterpret_cast<ethernet_header*>(const_cast<uint8_t*>(pkt->getData()) + eth->offset);

        std::memcpy(raw->srcMac, srcMac.bytes.data(), 6);
        std::memcpy(raw->dstMac, dstMac.bytes.data(), 6);
        return true;
    }

    io::Driver& driver_;
    arp::ArpResolver& arp_;
};

} // namespace snet::pp