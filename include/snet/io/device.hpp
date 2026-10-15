#pragma once

#include <string>

#include <snet/io/types.hpp>
#include <snet/layers/l2/mac_address.hpp>

#include <casket/nonstd/span.hpp>

namespace snet::io
{

/// @brief Unique device identifier type.
using DeviceId = uint32_t;

/// @brief Sentinel value indicating an invalid device identifier.
inline constexpr DeviceId kInvalidDevice = ~0u;

/// @brief Abstract network device interface.
///
/// Represents a single network interface exposed by a driver and provides
/// access to its properties and raw transmission capabilities.
class Device
{
public:
    /// @brief Virtual destructor.
    virtual ~Device() noexcept = default;

    /// @brief Gets device identifier.
    /// @return Unique device identifier.
    virtual DeviceId id() const noexcept = 0;

    /// @brief Gets device name.
    /// @return Interface name.
    virtual const std::string& name() const noexcept = 0;

    /// @brief Gets interface index.
    /// @return Kernel interface index.
    virtual uint32_t ifindex() const noexcept = 0;

    /// @brief Gets MAC address.
    /// @return Device MAC address.
    virtual const layers::MacAddress& mac() const noexcept = 0;

    /// @brief Gets MTU.
    /// @return Maximum transmission unit in bytes.
    virtual uint32_t mtu() const noexcept = 0;

    /// @brief Gets snapshot length.
    /// @return Capture snapshot length in bytes.
    virtual uint32_t snaplen() const noexcept = 0;

    /// @brief Checks whether the interface is up.
    /// @return True if the interface is up.
    virtual bool up() const noexcept = 0;

    /// @brief Sends raw data through this device.
    /// @param[in] data Pointer to the data buffer.
    /// @param[in] length Number of bytes to send.
    /// @return True on success, false otherwise.
    virtual bool send(const uint8_t* data, size_t length) noexcept = 0;
};

} // namespace snet::io