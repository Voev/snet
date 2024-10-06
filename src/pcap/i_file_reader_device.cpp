#include <fstream>
#include <snet/pcap/i_file_reader_device.hpp>
#include <snet/pcap/pcap_file_reader_device.hpp>

namespace snet::pcap
{

IFileReaderDevice::IFileReaderDevice(const std::string& fileName)
    : IFileDevice(fileName)
{
    numOfPacketsNotParsed_ = 0;
    numOfPacketsRead_ = 0;
}

IFileReaderDevice* IFileReaderDevice::getReader(const std::string& fileName)
{
    const auto extensionPos = fileName.find_last_of('.');
    const auto fileExtension =
        extensionPos != std::string::npos ? fileName.substr(extensionPos) : "";

    return new PcapFileReaderDevice(fileName);
}

uint64_t IFileReaderDevice::getFileSize() const
{
    std::ifstream fileStream(fileName_.c_str(),
                             std::ifstream::ate | std::ifstream::binary);
    return fileStream.tellg();
}

} // namespace snet::pcap