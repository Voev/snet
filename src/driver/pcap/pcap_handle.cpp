#include <pcap.h>
#include "pcap_handle.hpp"

namespace snet::driver
{

void PcapHandle::reset(PcapType* pcapDescriptor) noexcept
{
    PcapType* oldDescriptor = descriptor_;
    descriptor_ = pcapDescriptor;
    if (oldDescriptor != nullptr)
    {
        pcap_close(oldDescriptor);
    }
}

const char* PcapHandle::getLastError() const noexcept
{
    if (!isValid())
    {
        static char const* const noHandleError = "Invalid handle";
        return noHandleError;
    }

    return pcap_geterr(descriptor_);
}

} // namespace snet::pcap