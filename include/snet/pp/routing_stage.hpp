#pragma once

#include <snet/pp/packet_pipeline.hpp>
#include <snet/io/driver.hpp>
#include <snet/layers/protocol.hpp>

#include <unordered_map>

namespace snet::pp
{

class RoutingStage final : public IPacketStage
{
public:
    const char* name() const noexcept override
    {
        return "RoutingStage";
    }

    void setPeer(io::DeviceId a, io::DeviceId b)
    {
        peer_[a] = b;
        peer_[b] = a;
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        auto* ip = pkt->findLayer(layers::IPv4);
        if (!ip)
            return StageResult::Continue;

        auto ipHdr = pkt->getHeader<layers::IPv4Header>(*ip);
        const layers::IPv4Address dstIp = static_cast<layers::IPv4Address>(ipHdr.dstAddr());

        if (isLocal(ctx.ingress, dstIp))
        {
            ctx.egress = io::kInvalidDevice;
            return StageResult::Continue;
        }

        auto it = peer_.find(ctx.ingress);
        if (it == peer_.end())
            return StageResult::Drop;

        ctx.egress = it->second;
        ctx.nextHopIp = dstIp;
        return StageResult::Continue;
    }

    void setLocal(io::DeviceId iface, layers::IPv4Address ip)
    {
        local_[iface] = ip;
    }

private:
    bool isLocal(io::DeviceId iface, layers::IPv4Address ip) const
    {
        auto it = local_.find(iface);
        return it != local_.end() && it->second == ip;
    }

    std::unordered_map<io::DeviceId, io::DeviceId> peer_;
    std::unordered_map<io::DeviceId, layers::IPv4Address> local_;
};

} // namespace snet::pp