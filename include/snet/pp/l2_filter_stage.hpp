#pragma once

#include <snet/pp/packet_pipeline.hpp>
#include <snet/io/driver.hpp>
#include <snet/layers/protocol.hpp>

#include <cstring>

namespace snet::pp
{

class L2FilterStage final : public IPacketStage
{
public:
    explicit L2FilterStage(io::Driver& driver)
        : driver_(driver)
    {
    }

    const char* name() const noexcept override
    {
        return "L2FilterStage";
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        auto devCount = driver_.deviceCount();
        io::Device* device{nullptr};

        for (size_t i = 0; i < devCount; ++i)
        {
            device = driver_.deviceAt(i);
            if (device && device->id() == ctx.ingress)
            {
                break;
            }
        }

        if (!device)
        {
            return StageResult::Drop;
        }

        auto* eth = pkt->findLayer(layers::Ethernet);
        if (!eth)
            return StageResult::Drop;

        auto ethHdr = pkt->getHeader<layers::EthernetHeader>(*eth);
        layers::MacAddress dst(ethHdr.dstMac());

        if (dst.isBroadcast() || dst.isMulticast())
            return StageResult::Continue;

        if (dst == device->mac())
            return StageResult::Continue;

        return StageResult::Drop;
    }
private:
    io::Driver& driver_;
};

} // namespace snet::pp