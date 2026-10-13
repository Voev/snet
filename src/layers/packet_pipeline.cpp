#include <snet/layers/packet_pipeline.hpp>

namespace snet::layers
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
    for (size_t i = 0; i < stages_.size(); ++i)
    {
        switch (stages_[i]->process(pkt, ingress))
        {
        case StageResult::Continue:
            break;
        case StageResult::Consumed:
            return PacketVerdict::Consumed;
        case StageResult::Drop:
            return PacketVerdict::Drop;
        case StageResult::Pending:
            pending_.push_back({pkt, ingress, i, Clock::now() + kPendingTimeout});
            return PacketVerdict::Pending;
        }
    }
    return PacketVerdict::Pass;
}

void PacketPipeline::onTick(std::vector<ReadyItem>& ready)
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
            auto r = (i == p.stageIndex) ? stages_[i]->resume(p.pkt, p.ingress) : stages_[i]->process(p.pkt, p.ingress);

            if (r == StageResult::Continue)
            {
                ++i;
                continue;
            }
            if (r == StageResult::Pending)
            {
                if (now >= p.deadline)
                {
                    fail = true;
                }
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
            ready.push_back({p.pkt, true});
        else if (fail)
            ready.push_back({p.pkt, false});
    }

    pending_ = std::move(stillPending);
}

} // namespace snet::layers