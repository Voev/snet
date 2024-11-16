#pragma once
#include <memory>
#include <snet/pcap/i_file_device.hpp>
#include <snet/layers/raw_packet.hpp>

namespace snet::pcap
{

/**
 * @class IFileReaderDevice
 * An abstract class (cannot be instantiated, has a private c'tor) which is the
 * parent class for file reader devices
 */
class IFileReaderDevice : public IFileDevice
{
protected:
    uint32_t numOfPacketsRead_;
    uint32_t numOfPacketsNotParsed_;

    /**
     * A constructor for this class that gets the pcap full path file name to
     * open. Notice that after calling this constructor the file isn't opened
     * yet, so reading packets will fail. For opening the file call open()
     * @param[in] fileName The full path of the file to read
     */
    IFileReaderDevice(const std::string& fileName);

public:
    /**
     * A destructor for this class
     */
    virtual ~IFileReaderDevice() = default;

    /**
     * @return The file size in bytes
     */
    uint64_t getFileSize() const;

    virtual bool getNextPacket(layers::RawPacket& rawPacket) = 0;

    /**
     * A static method that creates an instance of the reader best fit to read
     * the file. It decides by the file extension: for .pcapng files it returns
     * an instance of PcapNgFileReaderDevice and for all other extensions it
     * returns an instance of PcapFileReaderDevice
     * @param[in] fileName The file name to open
     * @return An instance of the reader to read the file. Notice you should
     * free this instance when done using it
     */
    static std::unique_ptr<IFileReaderDevice> getReader(const std::string& fileName);
};

} // namespace snet::pcap