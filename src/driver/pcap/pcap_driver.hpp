#pragma once
#include <snet/io.hpp>
#include "pcap_handle.hpp"

namespace snet::driver
{

class PacketPool;

class Pcap final : public io::Driver
{
public:
    Pcap(const io::DriverConfig& config);

    ~Pcap() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    const char* getName() const override;

    Status configure(const io::Config& config) override;

    Status start() override;

    Status stop() override;

    Status interrupt() override;

    RecvStatus receivePacket(layers::Packet** packet) override;

    RecvStatus receivePackets(layers::Packet** packet, uint16_t* packetCount, uint16_t maxCount) override;

    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    Status inject(const uint8_t* data, uint32_t dataLength) override;

    int getSnaplen() const override;

    layers::LinkLayerType getDataLinkType() const override;
    
    Status getMsgPoolInfo(PacketPoolInfo* info) override;

    Status getStats(Stats* stats) override;

    void resetStats() override;

private:
    Status startLive();

    Status startOffline();

    Status applyFilterAndFinish();

    Status setNonBlocking(bool nb);

    Status installFilter(const std::string& filter);

    Status updateHwStats() noexcept;

private:
    std::unique_ptr<PacketPool> pool_;
    Stats stats_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    std::string device_;
    std::string filter_;
    PcapHandle handle_;
    FILE* fp_;
    unsigned int snaplen_;
    int timeout_;
    int bufferSize_;
    Mode mode_;
    uint32_t netmask_;
    uint32_t hwupdateCount_;
    U32Counter recvCounter_;
    U32Counter dropCounter_;
    bool promiscMode_;
    bool immediateMode_;
    bool nonblocking_;
    volatile bool interrupted_;
};

} // namespace snet::driver