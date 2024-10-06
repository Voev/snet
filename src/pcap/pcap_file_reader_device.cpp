#include <pcap.h>
#include <cstring>
#include <snet/pcap/pcap_file_reader_device.hpp>
#include <snet/log/log_manager.hpp>

namespace snet::pcap
{

bool PcapFileReaderDevice::open()
{
    numOfPacketsRead_ = 0;
    numOfPacketsNotParsed_ = 0;

    if (descriptor_ != nullptr)
    {
        log::debug("Pcap descriptor already opened. Nothing to do");
        return true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    auto pcapDescriptor =
        PcapHandle(pcap_open_offline(fileName_.c_str(), errbuf));
    if (pcapDescriptor == nullptr)
    {
        log::error("Cannot open file reader device for filename '{}': {}",
                   fileName_, errbuf);
        deviceOpened_ = false;
        return false;
    }

    int linkLayer = pcap_datalink(pcapDescriptor.get());
    if (!RawPacket::isLinkTypeValid(linkLayer))
    {
        log::error("Invalid link layer ({}) for reader device filename '{}'",
                   linkLayer, fileName_);
        deviceOpened_ = false;
        return false;
    }

    m_PcapLinkLayerType = static_cast<LinkLayerType>(linkLayer);
    descriptor_ = std::move(pcapDescriptor);
    deviceOpened_ = true;
    return true;
}

void PcapFileReaderDevice::getStatistics(PcapStats& stats) const
{
    stats.packetsRecv = numOfPacketsRead_;
    stats.packetsDrop = numOfPacketsNotParsed_;
    stats.packetsDropByInterface = 0;
    log::debug("Statistics received for reader device for filename '{}'",
               fileName_);
}

bool PcapFileReaderDevice::getNextPacket(RawPacket& rawPacket)
{
    rawPacket.clear();
    if (descriptor_ == nullptr)
    {
        log::error("File device '{}' not opened", fileName_);
        return false;
    }
    pcap_pkthdr pkthdr;
    const uint8_t* pPacketData = pcap_next(descriptor_.get(), &pkthdr);
    if (pPacketData == nullptr)
    {
        log::debug("Packet could not be read. Probably end-of-file");
        return false;
    }

    uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
    memcpy(pMyPacketData, pPacketData, pkthdr.caplen);

    struct timeval ts = pkthdr.ts;

    if (!rawPacket.setRawData(pMyPacketData, pkthdr.caplen, ts,
                              static_cast<LinkLayerType>(m_PcapLinkLayerType),
                              pkthdr.len))
    {
        log::error("Couldn't set data to raw packet");
        return false;
    }
    numOfPacketsRead_++;
    return true;
}

} // namespace snet::pcap