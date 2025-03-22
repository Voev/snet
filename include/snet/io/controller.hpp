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

    void inject(const uint8_t* data, uint32_t data_len);

    void interrupt();

    int getDataLinkType();

    RecvStatus receivePacket(RawPacket** rawPacket);

    void finalizePacket(RawPacket* rawPacket, Verdict verdict);

    void getMsgPoolInfo(PacketPoolInfo* info);
    State getState() const;
    int getSnapLen();
    uint32_t getCapabilities();
    void getStats(Stats* stats);
    void resetStats();

private:
    std::shared_ptr<Driver> driver_;
    State state_;
};

} // namespace snet::io
