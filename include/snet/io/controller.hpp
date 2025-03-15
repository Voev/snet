#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <snet/io/driver.hpp>
#include <snet/io/config.hpp>

namespace snet::io
{

class Controller
{
public:
    enum class State
    {
        Unknown = 0,
        Uninitialized,
        Initialized,
        Started,
        Stopped,
    };

    Controller();
    ~Controller() noexcept;

    void init(const Config& config);
    void final();

    void start();
    void stop();

    void setFilter(std::string_view filter);

    void inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len);
    void injectRelative(SNetIO_Message_t* msg, const uint8_t* data, uint32_t data_len, int reverse);

    void interrupt();

    int getDataLinkType();

    DAQ_RecvStatus receiveMessages(SNetIO_Message_t* msgs[], const std::size_t maxSize,
                                   std::size_t* received);
    void finalizeMessage(SNetIO_Message_t* msg, DAQ_Verdict verdict);
    void getMsgPoolInfo(DAQ_MsgPoolInfo_t* info);

    State getState() const;
    int getSnapLen();
    uint32_t getCapabilities();
    void getStats(DAQ_Stats_t* stats);
    void resetStats();

private:
    std::shared_ptr<Driver> driver_;
    State state_;
};

} // namespace snet::io
