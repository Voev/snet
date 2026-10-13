#pragma once
#include <string>
#include <cstdint>

#include <snet/io/device.hpp>

#include "afpacket_types.hpp"
#include "afpacket_fanout.hpp"

namespace snet::driver
{

class AFPacketDriver;

class Instance final : public io::Device
{
public:
    explicit Instance(AFPacketDriver& driver, io::DeviceId id);

    ~Instance() noexcept;

    Instance(const Instance&) = delete;

    Instance& operator=(const Instance&) = delete;

    io::DeviceId id() const noexcept override
    {
        return id_;
    }

    const std::string& name() const noexcept override
    {
        return name_;
    }

    uint32_t ifindex() const noexcept override
    {
        return index_;
    }

    const layers::MacAddress& mac() const noexcept override
    {
        return mac_;
    }

    uint32_t mtu() const noexcept override
    {
        return mtu_;
    }

    uint32_t snaplen() const noexcept override
    {
        return actualSnaplen_;
    }

    bool up() const noexcept override
    {
        return up_;
    }

    int fd() const noexcept
    {
        return fd_;
    }

    bool send(const uint8_t* data, size_t length) noexcept override;

    bool create(const std::string& name);
    void destroy();

    struct RingConfig
    {
        uint32_t ringSizeHint{0};
        uint32_t snaplen{0};
        bool useTxRing{false};
    };
    bool createRings(const RingConfig& cfg);

    bool bindTo(int protocol);

    bool configureFanout(afpacket::Fanout::Type fanoutType, afpacket::Fanout::Flags fanoutFlags);

    enum class RxStatus
    {
        Ok,
        NoPacket,
        Corrupt
    };

    struct RxFrame
    {
        uint8_t* data{nullptr};
        uint32_t caplen{0};
        uint32_t len{0};
        RingEntry* entry{nullptr};
    };

    RxStatus receive(RxFrame& out) noexcept;
    void releaseFrame(RingEntry* entry) noexcept;
    void releaseOutstandingFrames() noexcept;

    uint32_t rxFrameCount() const noexcept
    {
        return rxRing_.layout.tp_frame_nr;
    }

private:
    bool calculateFrameSize(uint32_t snaplen);
    bool calculateLayout(tpacket_req& layout, int order) const;
    bool createRxRing();
    bool createTxRing();
    bool mmapRings();
    bool setupRing(Ring& ring);

    bool sendRing(const uint8_t* data, size_t length) noexcept;
    bool sendDirect(const uint8_t* data, size_t length) noexcept;

private:
    AFPacketDriver& driver_;
    io::DeviceId id_{io::kInvalidDevice};
    layers::MacAddress mac_{};
    std::string name_;
    int fd_{-1};
    uint32_t index_{0};
    uint32_t tpReserve_{0};
    uint32_t tpFrameSize_{0};
    uint32_t tpHdrlen_{0};
    uint32_t actualSnaplen_{0};
    uint32_t ringSizeHint_{0};
    uint32_t snaplenCfg_{0};
    uint32_t mtu_{0};
    uint32_t macoff_{0};
    bool up_{false};
    bool useTxRing_{false};
    void* buffer_{nullptr};
    Ring rxRing_{};
    Ring txRing_{};
};

} // namespace snet::driver