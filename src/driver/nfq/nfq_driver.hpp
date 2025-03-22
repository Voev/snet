#pragma once
#include <snet/io.hpp>

namespace snet::driver
{

class NfQueue final : public io::Driver
{
public:
    NfQueue(const io::DriverConfig& config);
    ~NfQueue() noexcept;

    //Status getMsgPoolInfo(PacketPoolInfo* info) override;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    Status start() override;

    Status stop() override;

    Status interrupt() override;

    RecvStatus receivePacket(io::RawPacket** packet) override;

    Status finalizePacket(io::RawPacket* rawPacket, Verdict verdict) override;
    int getSnaplen() const override;
    uint32_t getType() const override;
    uint32_t getCapabilities() const override;
    io::LinkLayerType getDataLinkType() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::driver