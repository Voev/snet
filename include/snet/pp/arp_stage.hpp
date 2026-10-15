#pragma once

#include <snet/pp/packet_pipeline.hpp>
#include <snet/arp/arp_resolver.hpp>

namespace snet::pp
{

class ArpInterceptorStage final : public IPacketStage
{
public:
    explicit ArpInterceptorStage(arp::ArpResolver& arp)
        : arp_(arp)
    {
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        if (arp_.handle(pkt, ctx.ingress))
        {
            return StageResult::Consumed;
        }
        return StageResult::Continue;
    }

private:
    arp::ArpResolver& arp_;
};

} // namespace snet::pp