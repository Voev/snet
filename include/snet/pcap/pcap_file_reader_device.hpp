#pragma once
#include <snet/pcap/i_file_reader_device.hpp>
#include <snet/layers/raw_packet.hpp>

namespace snet::pcap
{

/**
 * @class PcapFileReaderDevice
 * A class for opening a pcap file in read-only mode. This class enable to open
 * the file and read all packets, packet-by-packet
 */
class PcapFileReaderDevice : public IFileReaderDevice
{
private:
    layers::LinkLayerType m_PcapLinkLayerType;

    // private copy c'tor
    PcapFileReaderDevice(const PcapFileReaderDevice& other) = delete;
    PcapFileReaderDevice& operator=(const PcapFileReaderDevice& other) = delete;

public:
    /**
     * A constructor for this class that gets the pcap full path file name to
     * open. Notice that after calling this constructor the file isn't opened
     * yet, so reading packets will fail. For opening the file call open()
     * @param[in] fileName The full path of the file to read
     */
    PcapFileReaderDevice(const std::string& fileName)
        : IFileReaderDevice(fileName)
        , m_PcapLinkLayerType(layers::LINKTYPE_ETHERNET)
    {
    }

    /**
     * A destructor for this class
     */
    virtual ~PcapFileReaderDevice() = default;

    /**
     * @return The link layer type of this file
     */
    layers::LinkLayerType getLinkLayerType() const
    {
        return m_PcapLinkLayerType;
    }

    // overridden methods

    /**
     * Read the next packet from the file. Before using this method please
     * verify the file is opened using open()
     * @param[out] rawPacket A reference for an empty RawPacket where the packet
     * will be written
     * @return True if a packet was read successfully. False will be returned if
     * the file isn't opened (also, an error log will be printed) or if reached
     * end-of-file
     */
    bool getNextPacket(layers::RawPacket& rawPacket) override;

    /**
     * Open the file name which path was specified in the constructor in a
     * read-only mode
     * @return True if file was opened successfully or if file is already
     * opened. False if opening the file failed for some reason (for example:
     * file path does not exist)
     */
    bool open() override;

    /**
     * Get statistics of packets read so far. In the PcapStats struct, only the
     * packetsRecv member is relevant. The rest of the members will contain 0
     * @param[out] stats The stats struct where stats are returned
     */
    void getStatistics(PcapStats& stats) const override;
};

} // namespace snet::pcap