#pragma once
#include <snet/io.hpp>

namespace snet::driver
{

class NfQueue final : public io::Driver
{
public:
    NfQueue(const io::DriverConfig& config);

    ~NfQueue() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    Status configure(const io::Config& config) override;

    Status start() override;

    Status stop() override;

    Status interrupt() override;

    RecvStatus receivePacket(layers::Packet** packet) override;

    Status inject(const uint8_t* data, uint32_t data_len) override;

    Status finalizePacket(layers::Packet* packet, Verdict verdict) override;

    int getSnaplen() const override;

    layers::LinkLayerType getDataLinkType() const override;
    
    Status getMsgPoolInfo(PacketPoolInfo* info) override;

    const char* getName() const override;

    Status getStats(Stats* stats) override;

    void resetStats() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::driver