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

    RecvStatus receivePacket(io::RawPacket** packet) override;

    Status finalizePacket(io::RawPacket* rawPacket, Verdict verdict) override;

    io::LinkLayerType getDataLinkType() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::driver