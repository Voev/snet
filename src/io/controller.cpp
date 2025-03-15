#include <stdexcept>
#include <cstring>
#include <filesystem>
#include <snet/io/controller.hpp>
#include <snet/io/config.hpp>

namespace snet::io
{

Controller::Controller()
    : state_(State::Uninitialized)
{
}

Controller::~Controller() noexcept
{
}

void Controller::init(const Config& config)
{
    auto drvConfigs = config.getDrivers();

    std::shared_ptr<Driver> previousDriver = nullptr;
    for (auto& drvConf : drvConfigs)
    {
        std::function<DriverCreator> createDriver = import_alias<DriverCreator>(drvConf.getPath(), "CreateDriver");

        auto currentDriver = createDriver(drvConf);
        if (previousDriver)
        {
            /// @todo: check for filter
            previousDriver->setNext(currentDriver);
        }
        else
        {
            /// @todo: check for source
            driver_ = currentDriver;
        }
        previousDriver = currentDriver;
    }

    state_ = State::Initialized;
}

void Controller::final()
{
}

void Controller::setFilter(std::string_view filter)
{
    if (state_ != State::Initialized)
    {
        throw std::runtime_error("Can't set filter on uninitialized instance!");
    }

    int rval = driver_->setFilter(filter.data());
    if (rval != DAQ_SUCCESS)
    {
        throw std::runtime_error("failed to set filter");
    }
}

void Controller::start()
{
    if (state_ != State::Initialized)
    {
        throw std::runtime_error("Can't start an instance that isn't initialized!");
    }

    int ret = driver_->start();
    if (ret == DAQ_SUCCESS)
        state_ = State::Started;
    else
        throw std::runtime_error("failed to start");
}

void Controller::inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len)
{

    if (!hdr)
    {
        throw std::invalid_argument("No message header given!");
    }

    if (!data)
    {
        throw std::runtime_error("No message data specified!");
    }

    int ret = driver_->inject(type, hdr, data, data_len);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to inject");
}

void Controller::injectRelative(SNetIO_Message_t* msg, const uint8_t* data, uint32_t data_len,
                                int reverse)
{

    if (!msg)
    {
        throw std::invalid_argument("No original message header given!");
    }

    if (!data)
    {
        throw std::invalid_argument("No message data given!");
    }

    int ret = driver_->injectRelative(msg, data, data_len, reverse);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to inject relative");
}

void Controller::interrupt()
{
    int ret = driver_->interrupt();
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to interrupt");
}

void Controller::stop()
{
    if (state_ != State::Started)
    {
        throw std::runtime_error("Can't stop an instance that hasn't started!");
    }

    int ret = driver_->stop();
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to stop");
    else
        state_ = State::Stopped;
}

Controller::State Controller::getState() const
{
    return state_;
}

void Controller::getStats(DAQ_Stats_t* stats)
{
    if (!stats)
    {
        throw std::invalid_argument("No place to put the statistics!");
    }

    int ret = driver_->getStats(stats);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to stop");
}

void Controller::resetStats()
{
    driver_->resetStats();
}

int Controller::getSnapLen()
{
    return driver_->getSnaplen();
}

uint32_t Controller::getCapabilities()
{
    return driver_->getCapabilities();
}

int Controller::getDataLinkType()
{
    return driver_->getDataLinkType();
}

DAQ_RecvStatus Controller::receiveMessages(SNetIO_Message_t* msgs[], const std::size_t maxSize,
                                           std::size_t* received)
{
    if (!msgs)
    {
        return DAQ_RSTAT_INVALID;
    }

    if (!maxSize)
    {
        return DAQ_RSTAT_OK;
    }

    return driver_->receiveMsgs(msgs, maxSize, received);
}

void Controller::finalizeMessage(SNetIO_Message_t* msg, DAQ_Verdict verdict)
{

    if (!msg)
        throw std::invalid_argument("msg");

    int ret = driver_->finalizeMsg(msg, verdict);
    if (DAQ_SUCCESS != ret)
        throw std::runtime_error("failed to finalize message");
}

void Controller::getMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
{
    if (!info)
        throw std::invalid_argument("info");

    int ret = driver_->getMsgPoolInfo(info);
    if (DAQ_SUCCESS != ret)
        throw std::runtime_error("failed to get message pool");
}

} // namespace snet::io
