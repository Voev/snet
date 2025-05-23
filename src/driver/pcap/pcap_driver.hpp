#pragma once
#include <snet/io.hpp>

namespace snet::driver
{

class Pcap final : public io::Driver
{
public:
    Pcap(const io::DriverConfig& config);
    ~Pcap() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    Status start() override;

    Status stop() override;

    Status interrupt() override;

    Status setFilter(const std::string& filter) override;

    Status inject(const uint8_t* data, uint32_t data_len) override;

    RecvStatus receivePacket(io::RawPacket** packet) override;

    Status finalizePacket(io::RawPacket* rawPacket, Verdict verdict) override;
    int getSnaplen() const override;
    uint32_t getType() const override;
    uint32_t getCapabilities() const override;
    io::LinkLayerType getDataLinkType() const override;
    Status getMsgPoolInfo(PacketPoolInfo* info) override;

    Status getStats(Stats* stats) override;
    void resetStats() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::driver