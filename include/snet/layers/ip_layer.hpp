#pragma once

#include <snet/ip/ip_address.hpp>

#include <snet/layers/layer.hpp>

namespace snet::layers {
/**
 * @class IPLayer
 * This is an interface (abstract class) implemented in the IP layers (IPv4Layer and IPv6Layer).
 * It provides methods to fetch the source and destination IP addresses in an abdtract way
 * that hides the IP type (IPv4 or IPv6). This is useful for use-cases in which the IP type doesn't matter.
 * For example: if you're only interested in printing the IP address the IP type shouldn't matter.
 */
class IPLayer {
protected:
    IPLayer() = default;

public:
    /**
     * An abstract method to get the source IP address
     * @return An IPAddress object containing the source address
     */
    virtual ip::IPAddress getSrcIPAddress() const = 0;

    /**
     * An abstract method to get the destination IP address
     * @return An IPAddress object containing the destination address
     */
    virtual ip::IPAddress getDstIPAddress() const = 0;

    /**
     * An empty destructor
     */
    virtual ~IPLayer() = default;
};

} // namespace snet::layers
