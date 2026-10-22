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

    const char* name() const noexcept override
    {
        return "SessionStage";
    }

    StageResult process(layers::Packet* pkt, PacketContext& ctx) override
    {
        (void)ctx;

        if (!pkt->findLayer(layers::TCP))
            return StageResult::Continue;

        auto res = mgr_.processPacket(pkt);
        if (res.passes())
        {
            return StageResult::Continue;
        }
        return StageResult::Drop;
    }

private:
    SessionManagerType& mgr_;
};

} // namespace snet::pp