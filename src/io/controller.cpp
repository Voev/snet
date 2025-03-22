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

    auto status = driver_->setFilter(filter.data());
    if (status != Status::Success)
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

    auto status = driver_->start();
    if (status == Status::Success)
        state_ = State::Started;
    else
        throw std::runtime_error("failed to start");
}

void Controller::inject(const uint8_t* data, uint32_t data_len)
{
    auto status = driver_->inject(data, data_len);
    if (status != Status::Success)
        throw std::runtime_error("failed to inject");
}

void Controller::interrupt()
{
    auto status = driver_->interrupt();
    if (status != Status::Success)
        throw std::runtime_error("failed to interrupt");
}

void Controller::stop()
{
    if (state_ != State::Started)
    {
        throw std::runtime_error("Can't stop an instance that hasn't started!");
    }

    auto status = driver_->stop();
    if (status != Status::Success)
        throw std::runtime_error("failed to stop");
    else
        state_ = State::Stopped;
}

Controller::State Controller::getState() const
{
    return state_;
}

void Controller::getStats(Stats* stats)
{
    if (!stats)
    {
        throw std::invalid_argument("No place to put the statistics!");
    }

    auto status = driver_->getStats(stats);
    if (status != Status::Success)
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

RecvStatus Controller::receivePacket(RawPacket** rawPacket)
{
    return driver_->receivePacket(rawPacket);
}

void Controller::finalizePacket(RawPacket* rawPacket, Verdict verdict)
{
    auto status = driver_->finalizePacket(rawPacket, verdict);
    if (status != Status::Success)
        throw std::runtime_error("failed to finalize message");
}

void Controller::getMsgPoolInfo(PacketPoolInfo* info)
{
    if (!info)
        throw std::invalid_argument("info");

    auto status = driver_->getMsgPoolInfo(info);
    if (status != Status::Success)
        throw std::runtime_error("failed to get message pool");
}

} // namespace snet::io
