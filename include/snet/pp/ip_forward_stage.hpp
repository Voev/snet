#pragma once

#include <snet/pp/packet_pipeline.hpp>
#include <snet/layers/protocol.hpp>

namespace snet::pp {

class IpForwardStage final : public IPacketStage {
public:
    const char* name() const noexcept override
    {
        return "IpForwardStage";
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        if (ctx.egress == io::kInvalidDevice)
            return StageResult::Continue;

        auto* ip = pkt->findLayer(layers::IPv4);
        if (!ip)
            return StageResult::Continue;

        auto ipHdr = pkt->getHeader<layers::IPv4Header>(*ip);
        if (ipHdr.ttl() <= 1)
            return StageResult::Drop;

        //ipHdr.setTTL(ipHdr.getTTL() - 1);
        //ipHdr.computeChecksum();

        return StageResult::Continue;
    }
};

} // namespace snet::pp