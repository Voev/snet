#pragma once
#include <snet/layers/l3/ip_address.hpp>

namespace snet::layers
{

/// @brief Interface for IP layers (IPv4/IPv6) providing common IP operations.
/// @details Abstracts IP type specifics for scenarios where IP version doesn't matter.
class IPLayer
{
protected:
    /// @brief Default constructor.
    IPLayer() = default;

public:
    /// @brief Get source IP address.
    /// @return IPAddress containing source address.
    virtual IPAddress getSrcIPAddress() const = 0;

    /// @brief Get destination IP address
    /// @return IPAddress containing destination address.
    virtual IPAddress getDstIPAddress() const = 0;

    /// @brief Virtual destructor.
    virtual ~IPLayer() = default;
};

} // namespace snet::layers
