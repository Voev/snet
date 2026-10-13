#pragma once

#include <string>

#include <snet/io/types.hpp>
#include <snet/layers/l2/mac_address.hpp>

#include <casket/nonstd/span.hpp>

namespace snet::io
{

using DeviceId = uint32_t;
inline constexpr DeviceId kInvalidDevice = ~0u;

class Device
{
public:
    virtual ~Device() noexcept = default;

    virtual DeviceId id() const noexcept = 0;

    virtual const std::string& name() const noexcept = 0;

    virtual uint32_t ifindex() const noexcept = 0;

    virtual const layers::MacAddress& mac() const noexcept = 0;

    virtual uint32_t mtu() const noexcept = 0;

    virtual uint32_t snaplen() const noexcept = 0;

    virtual bool up() const noexcept = 0;

    virtual bool send(const uint8_t* data, size_t length) noexcept = 0;
};

} // namespace snet::io