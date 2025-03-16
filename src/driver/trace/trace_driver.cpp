#include <optional>
#include <snet/io.hpp>

#include <casket/utils/string.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/filter/data_sink.hpp>

#include "trace_driver.hpp"

using namespace casket::utils;

namespace snet::driver
{

struct Trace::Impl
{
    std::unique_ptr<filter::DataSinkStream> sink;
    std::optional<std::string> filename;
    Stats stats;
};

Trace::Trace(const io::DriverConfig& config)
    : impl_(std::make_unique<Trace::Impl>())
{
    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "file"))
            impl_->filename = value;
    }
}

Status Trace::start()
{
    auto status = next_->start();
    if (status != Status::Success)
        return status;

    if (impl_->filename.has_value())
        impl_->sink = std::make_unique<filter::DataSinkStream>(impl_->filename.value(), false);
    else
        impl_->sink = std::make_unique<filter::DataSinkStream>(std::cout, "std::cout");

    return Status::Success;
}

Status Trace::stop()
{
    auto status = next_->stop();
    if (status != Status::Success)
        return status;

    impl_->sink.reset();
    return Status::Success;
}

Status Trace::getStats(Stats* stats)
{
    auto status{Status::Success};

    if (next_)
    {
        status = next_->getStats(stats);
        if (status == Status::Success)
        {
            for (int i = 0; i < MAX_Verdict; i++)
                stats->verdicts[i] = impl_->stats.verdicts[i];
            stats->packets_injected = impl_->stats.packets_injected;
        }
    }
    else
    {
        *stats = impl_->stats;
    }

    return status;
}

void Trace::resetStats()
{
    if (next_)
    {
        next_->resetStats();
    }
    memset(&impl_->stats, 0, sizeof(impl_->stats));
}

uint32_t Trace::getCapabilities() const
{
    uint32_t caps{0};
    if (next_)
    {
        caps |= next_->getCapabilities();
    }
    return caps;
}

const char* Verdict_strings[MAX_Verdict] = {
    "Pass",      // Verdict_PASS
    "Block",     // Verdict_BLOCK
    "Replace",   // Verdict_REPLACE
    "Whitelist", // Verdict_WHITELIST
    "Blacklist", // Verdict_BLACKLIST
    "Ignore"     // Verdict_IGNORE
};

Status Trace::finalizePacket(const io::RawPacket& rawPacket, Verdict verdict)
{
    impl_->stats.verdicts[verdict]++;

    return next_->finalizePacket(rawPacket, verdict);
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::Trace::create, CreateDriver)
