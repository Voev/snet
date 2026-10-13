#pragma once

#include <chrono>
#include <memory>
#include <vector>

#include <snet/layers/packet.hpp>
#include <snet/io/types.hpp>
#include <snet/io/device.hpp>

namespace snet::layers
{

enum class PacketVerdict
{
    Pass,
    Drop,
    Consumed,
    Pending,
};

enum class StageResult
{
    Continue,
    Consumed,
    Drop,
    Pending,
};

class IPacketStage
{
public:
    virtual ~IPacketStage() = default;

    virtual StageResult process(Packet* pkt, io::DeviceId ingress) = 0;

    virtual StageResult resume(Packet* pkt, io::DeviceId ingress)
    {
        return process(pkt, ingress);
    }
};

struct ReadyItem
{
    Packet* pkt{nullptr};
    bool ok{false};
};

class PacketPipeline
{
public:
    PacketPipeline() = default;

    void addStage(std::unique_ptr<IPacketStage> s);

    PacketVerdict onPacket(Packet* pkt, io::DeviceId ingress);
    void onTick(std::vector<ReadyItem>& ready);

    void clear()
    {
        stages_.clear();
        pending_.clear();
    }
    size_t size() const
    {
        return stages_.size();
    }
    bool empty() const
    {
        return stages_.empty();
    }

private:
    struct Pending
    {
        Packet* pkt{nullptr};
        io::DeviceId ingress{io::kInvalidDevice};
        size_t stageIndex{0};
        std::chrono::steady_clock::time_point deadline;
    };

    std::vector<std::unique_ptr<IPacketStage>> stages_;
    std::vector<Pending> pending_;
};

} // namespace snet::layers