#pragma once

#include <chrono>
#include <memory>
#include <vector>

#include <snet/layers/packet.hpp>
#include <snet/io/types.hpp>
#include <snet/io/device.hpp>

namespace snet::pp
{

/// @brief Final verdict produced by the packet pipeline.
enum class PacketVerdict
{
    Pass,     ///< Packet should be transmitted.
    Drop,     ///< Packet should be dropped.
    Consumed, ///< Packet was fully handled by a stage.
    Pending,  ///< Packet is deferred and awaiting a later tick.
};

/// @brief Result returned by a single pipeline stage.
enum class StageResult
{
    Continue, ///< Continue processing with the next stage.
    Consumed, ///< Packet was fully handled; stop the pipeline.
    Drop,     ///< Drop the packet; stop the pipeline.
    Pending,  ///< Defer the packet for later resumption.
};

/// @brief Per-packet processing context.
struct PacketContext
{
    io::DeviceId ingress{io::kInvalidDevice}; ///< Ingress device identifier.
    io::DeviceId egress{io::kInvalidDevice};  ///< Egress device identifier.
    layers::IPv4Address nextHopIp;
};

/// @brief Interface for a single packet processing stage.
class IPacketStage
{
public:
    using Packet = snet::layers::Packet;

    /// @brief Virtual destructor.
    virtual ~IPacketStage() = default;

    /// @brief Processes a packet.
    /// @param[in,out] pkt Packet to process.
    /// @param[in,out] ctx Processing context.
    /// @return Stage result.
    virtual StageResult process(Packet* pkt, PacketContext& ctx) = 0;

    /// @brief Resumes a previously deferred packet.
    /// @param[in,out] pkt Packet to resume.
    /// @param[in,out] ctx Processing context.
    /// @return Stage result. Default implementation calls process().
    virtual StageResult resume(Packet* pkt, PacketContext& ctx)
    {
        return process(pkt, ctx);
    }

    virtual void tick()
    {}
};

/// @brief Descriptor for a packet that became ready after being pending.
struct ReadyItem
{
    snet::layers::Packet* pkt{nullptr}; ///< Packet that is now ready.
    bool ok{false};       ///< Whether the packet completed successfully.
};

/// @brief Sequential pipeline of packet processing stages.
class PacketPipeline
{
public:
    using Packet = snet::layers::Packet;

    /// @brief Callback invoked when a pending packet becomes ready.
    /// @param[in] pkt Packet that became ready.
    /// @param[in] ctx Processing context.
    /// @param[in] ok Whether the packet completed successfully.
    using ReadyFn = std::function<void(layers::Packet*, PacketContext&, bool ok)>;

    /// @brief Default constructor.
    PacketPipeline() = default;

    /// @brief Appends a stage to the pipeline.
    /// @param[in] s Stage to append.
    void addStage(std::unique_ptr<IPacketStage> s);

    /// @brief Runs the pipeline on a newly received packet.
    /// @param[in] pkt Packet to process.
    /// @param[in] ingress Ingress device identifier.
    /// @return Final pipeline verdict.
    PacketVerdict onPacket(Packet* pkt, io::DeviceId ingress);

    /// @brief Advances deferred packets whose deadlines have expired.
    /// @param[in] onReady Callback invoked for each ready packet.
    void onTick(const ReadyFn& onReady);

    /// @brief Clears all stages and pending packets.
    void clear()
    {
        stages_.clear();
        pending_.clear();
    }

    /// @brief Gets number of stages.
    /// @return Number of registered stages.
    size_t size() const
    {
        return stages_.size();
    }

    /// @brief Checks whether the pipeline has no stages.
    /// @return True if no stages are registered.
    bool empty() const
    {
        return stages_.empty();
    }

private:
    /// @brief Deferred packet awaiting resumption.
    struct Pending
    {
        Packet* pkt{nullptr};                                 ///< Deferred packet.
        PacketContext ctx{};                                  ///< Processing context.
        size_t stageIndex{0};                                 ///< Index of the stage that deferred the packet.
        std::chrono::steady_clock::time_point deadline;       ///< Deadline for resumption.
    };

    std::vector<std::unique_ptr<IPacketStage>> stages_; ///< Registered pipeline stages.
    std::vector<Pending> pending_;                      ///< Deferred packets awaiting resumption.
};

} // namespace snet::layers