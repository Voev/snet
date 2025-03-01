#pragma once
#include <string_view>
#include <snet/io/daq.h>

namespace snet::dbus
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

    void start();
    void stop();
    void reload();

    void init(SNetIO_BaseConfig_t* config);
    void final();
    void setFilter(std::string_view filter);

    void inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len);
    void injectRelative(SNetIO_Message_t* msg, const uint8_t* data, uint32_t data_len, int reverse);

    void interrupt();

    int getDataLinkType();

    unsigned receiveMessages(const unsigned max_recv, SNetIO_Message_t* msgs[], DAQ_RecvStatus* rstat);
    void finalizeMessage(SNetIO_Message_t* msg, DAQ_Verdict verdict);
    void getMsgPoolInfo(DAQ_MsgPoolInfo_t* info);

    State getState() const;
    int getSnapLen();
    uint32_t getCapabilities();
    void getStats(DAQ_Stats_t* stats);
    void resetStats();

    const char* getError()
    {
        return instance_.errbuf;
    }

private:
    DAQ_Instance_t instance_;
    State state_;
};

} // namespace snet::dbus
