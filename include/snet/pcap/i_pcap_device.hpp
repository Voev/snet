#pragma once
#include <cstdint>
#include <string>
#include <snet/pcap/i_device.hpp>
#include <snet/pcap/pcap_handle.hpp>

namespace snet::pcap
{

class IPcapDevice : public IDevice
{
protected:
    PcapHandle descriptor_;

    // c'tor should not be public
    IPcapDevice()
        : IDevice()
    {
    }

public:
    /**
     * @struct PcapStats
     * A container for pcap device statistics
     */
    struct PcapStats
    {
        /** Number of packets received */
        uint64_t packetsRecv;
        /** Number of packets dropped */
        uint64_t packetsDrop;
        /** number of packets dropped by interface (not supported on all
         * platforms) */
        uint64_t packetsDropByInterface;
    };

    virtual ~IPcapDevice() = default;

    /**
     * Get statistics from the device
     * @param[out] stats An object containing the stats
     */
    virtual void getStatistics(PcapStats& stats) const = 0;
};

} // namespace snet::pcap