#pragma once
#include <snet/io.hpp>

namespace snet::drivers
{

class Trace final : public io::Driver
{
public:
    Trace(const io::DriverConfig& config);

    ~Trace() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    int start() override;

    int stop() override;

    int finalizeMsg(const SNetIO_Message_t* msg, DAQ_Verdict verdict) override;

    uint32_t getCapabilities() const override;

    int getStats(DAQ_Stats_t* stats) override;

    void resetStats() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::drivers