#include <snet/pp/packet_pipeline.hpp>

namespace snet::pp
{

namespace
{
using Clock = std::chrono::steady_clock;
constexpr auto kPendingTimeout = std::chrono::milliseconds(500);
} // namespace

void PacketPipeline::addStage(std::unique_ptr<IPacketStage> s)
{
    stages_.push_back(std::move(s));
}

PacketVerdict PacketPipeline::onPacket(Packet* pkt, io::DeviceId ingress)
{
    PacketContext ctx;
    ctx.ingress = ingress;

    for (size_t i = 0; i < stages_.size(); ++i)
    {
        switch (stages_[i]->process(pkt, ctx))
        {
        case StageResult::Continue:
            break;
        case StageResult::Consumed:
            return PacketVerdict::Consumed;
        case StageResult::Drop:
            return PacketVerdict::Drop;
        case StageResult::Pending:
            pending_.push_back({pkt, ctx, i, Clock::now() + kPendingTimeout});
            return PacketVerdict::Pending;
        }
    }
    return PacketVerdict::Pass;
}

void PacketPipeline::onTick(const ReadyFn& onReady)
{
    const auto now = Clock::now();
    std::vector<Pending> stillPending;
    stillPending.reserve(pending_.size());

    for (auto& p : pending_)
    {
        bool done = false;
        bool fail = false;
        size_t i = p.stageIndex;

        while (i < stages_.size())
        {
            auto r = (i == p.stageIndex) ? stages_[i]->resume(p.pkt, p.ctx) : stages_[i]->process(p.pkt, p.ctx);

            if (r == StageResult::Continue)
            {
                ++i;
                continue;
            }
            if (r == StageResult::Pending)
            {
                if (now >= p.deadline)
                    fail = true;
                else
                {
                    p.stageIndex = i;
                    stillPending.push_back(p);
                }
                break;
            }
            fail = true;
            break;
        }

        if (!fail && i == stages_.size())
            done = true;

        if (done)
            onReady(p.pkt, p.ctx, true);
        else if (fail)
            onReady(p.pkt, p.ctx, false);
    }

    pending_ = std::move(stillPending);
}

} // namespace snet::pp