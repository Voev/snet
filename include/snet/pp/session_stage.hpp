#pragma once

#include <snet/pp/packet_pipeline.hpp>

#include <snet/layers/protocol.hpp>
#include <snet/layers/packet_status.hpp>

namespace snet::pp {

template <typename SessionManagerType>
class SessionStage final : public IPacketStage {
public:
    using Session = typename SessionManagerType::Session;

    explicit SessionStage(SessionManagerType& mgr)
        : mgr_(mgr) {}

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        if (ctx.egress != io::kInvalidDevice)
            return StageResult::Continue;

        switch (mgr_.processPacket(pkt))
        {
        case layers::PacketStatus::UnknownStatus:
            return StageResult::Continue;
        case layers::PacketStatus::Error_NoMemory:
            return StageResult::Drop;
        default:
            return StageResult::Consumed;
        }
    }

private:
    SessionManagerType& mgr_;
};

} // namespace snet::pp