#pragma once
#include <string>
#include <cstdint>
#include "afpacket_types.hpp"

#include <linux/if_packet.h>

namespace snet::driver
{

struct RingEntry
{
    uint8_t* raw{nullptr};
    RingEntry* next{nullptr};
};

struct Ring
{
    tpacket_req layout{};
    uint32_t size{0};
    void* start{nullptr};
    RingEntry* entries{nullptr};
    RingEntry* cursor{nullptr};
};

class AFPacketDriver;

class Instance final
{
public:
    explicit Instance(AFPacketDriver& driver);
    ~Instance() noexcept;

    Instance(const Instance&) = delete;
    Instance& operator=(const Instance&) = delete;

    bool create(const std::string& name);

    void destroy();

    int fd() const noexcept
    {
        return fd_;
    }
    uint32_t index() const noexcept
    {
        return index_;
    }
    uint32_t snaplen() const noexcept
    {
        return actualSnaplen_;
    }
    uint32_t frameSize() const noexcept
    {
        return tpFrameSize_;
    }
    uint32_t hdrLen() const noexcept
    {
        return tpHdrlen_;
    }
    int mtu() const noexcept
    {
        return mtu_;
    }
    bool active() const noexcept
    {
        return active_;
    }
    void setActive(bool v) noexcept
    {
        active_ = v;
    }
    const std::string& name() const noexcept
    {
        return name_;
    }

    void setFrameSize(uint32_t v) noexcept
    {
        tpFrameSize_ = v;
    }
    void setActualSnaplen(uint32_t v) noexcept
    {
        actualSnaplen_ = v;
    }
    void setBuffer(void* buf) noexcept
    {
        buffer_ = buf;
    }
    void setRingSizeHint(uint32_t v) noexcept
    {
        ringSizeHint_ = v;
    }
    uint32_t ringSizeHint() const noexcept
    {
        return ringSizeHint_;
    }

    bool bindTo(int protocol);

    Instance* peer{nullptr};
    Ring rxRing;
    Ring txRing;

    uint32_t tpVersion{0};
    uint32_t tpReserve{0};

private:
    AFPacketDriver& driver_;
    int fd_{-1};
    uint32_t index_{0};
    uint32_t tpReserve_{0};
    uint32_t tpFrameSize_{0};
    uint32_t tpHdrlen_{0};
    uint32_t actualSnaplen_{0};
    uint32_t ringSizeHint_{0};
    int mtu_{0};
    bool active_{false};
    void* buffer_{nullptr};
    std::string name_;
};

} // namespace snet::driver