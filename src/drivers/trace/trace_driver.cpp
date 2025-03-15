#include <optional>
#include <snet/io.hpp>

#include <casket/utils/string.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/filter/data_sink.hpp>

#include "trace_driver.hpp"

using namespace casket::utils;

namespace snet::drivers
{

struct Trace::Impl
{
    std::unique_ptr<filter::DataSinkStream> sink;
    std::optional<std::string> filename;
    DAQ_Stats_t stats;
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

int Trace::start()
{
    int rval = next_->start();
    if (rval != DAQ_SUCCESS)
        return rval;

    if (impl_->filename.has_value())
        impl_->sink = std::make_unique<filter::DataSinkStream>(impl_->filename.value(), false);
    else
        impl_->sink = std::make_unique<filter::DataSinkStream>(std::cout, "std::cout");

    return DAQ_SUCCESS;
}

int Trace::stop()
{
    int rval = next_->stop();
    if (rval != DAQ_SUCCESS)
        return rval;

    impl_->sink.reset();

    return DAQ_SUCCESS;
}

int Trace::getStats(DAQ_Stats_t* stats)
{
    int rval = DAQ_SUCCESS;

    if (next_)
    {
        rval = next_->getStats(stats);
        if (rval == DAQ_SUCCESS)
        {
            for (int i = 0; i < MAX_DAQ_VERDICT; i++)
                stats->verdicts[i] = impl_->stats.verdicts[i];
            stats->packets_injected = impl_->stats.packets_injected;
        }
    }
    else
    {
        *stats = impl_->stats;
    }

    return rval;
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
    uint32_t caps{0};// = DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT;
    if (next_)
    {
        caps |= next_->getCapabilities();
    }
    return caps;
}

static const char* daq_verdict_strings[MAX_DAQ_VERDICT] = {
    "Pass",      // DAQ_VERDICT_PASS
    "Block",     // DAQ_VERDICT_BLOCK
    "Replace",   // DAQ_VERDICT_REPLACE
    "Whitelist", // DAQ_VERDICT_WHITELIST
    "Blacklist", // DAQ_VERDICT_BLACKLIST
    "Ignore"     // DAQ_VERDICT_IGNORE
};

int Trace::finalizeMsg(const SNetIO_Message_t* msg, DAQ_Verdict verdict)
{
    impl_->stats.verdicts[verdict]++;
    if (msg->type == DAQ_MSG_TYPE_PACKET)
    {
        DAQ_PktHdr_t* hdr = (DAQ_PktHdr_t*)msg->hdr;
        auto info =
            format("{}.{}({}): {}", (unsigned long)hdr->ts.tv_sec, (unsigned long)hdr->ts.tv_usec,
                   msg->data_len, daq_verdict_strings[verdict]);
        
        impl_->sink->start_msg();
        impl_->sink->write((uint8_t*)info.c_str(), info.size());
        impl_->sink->end_msg();
    }

    return next_->finalizeMsg(msg, verdict);
}

} // namespace snet::drivers

SNET_DLL_ALIAS(snet::drivers::Trace::create, CreateDriver)
