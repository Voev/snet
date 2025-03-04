#pragma once
#include <snet/io.hpp>
#include <snet/io/export_function.hpp>

namespace snet::drivers
{

class Pcap final : public io::Driver
{
public:
    Pcap(const io::DriverConfig& config);
    ~Pcap() noexcept;

    static std::shared_ptr<io::Driver> create(const io::DriverConfig& config);

    int start() override;

    int stop() override;

    int interrupt() override;

    int setFilter(const std::string& filter) override;

    int inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len) override;

    DAQ_RecvStatus receiveMsgs(SNetIO_Message_t* msgs[], const size_t maxSize,
                               size_t* received) override;

    int finalizeMsg(const SNetIO_Message_t* msg, DAQ_Verdict verdict) override;
    int getSnaplen() const override;
    uint32_t getType() const override;
    uint32_t getCapabilities() const override;
    int getDataLinkType() const override;
    int getMsgPoolInfo(DAQ_MsgPoolInfo_t* info) override;

    int getStats(DAQ_Stats_t* stats) override;
    void resetStats() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::drivers