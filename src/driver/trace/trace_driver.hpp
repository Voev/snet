#pragma once
#include <snet/io.hpp>

namespace snet::driver
{

class Trace final : public io::Driver
{
public:
    Trace(const io::DriverConfig& config);

    ~Trace() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    Status start() override;

    Status stop() override;

    Status finalizePacket(io::RawPacket* rawPacket, Verdict verdict) override;

    uint32_t getCapabilities() const override;

    Status getStats(Stats* stats) override;

    void resetStats() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::driver