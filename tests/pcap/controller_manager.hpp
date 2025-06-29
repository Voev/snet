#pragma once
#include <snet/io.hpp>
#include <casket/utils/singleton.hpp>

namespace snet
{

class ControllerManager final : public casket::Singleton<ControllerManager>
{
public:
    ControllerManager() = default;

    ~ControllerManager() = default;

    void loadDriver(const io::DriverConfig& config)
    {
        controller_.load(config);
    }

    std::shared_ptr<io::Driver> getDriver(const std::string& name)
    {
        return controller_.get(name);
    }

private:
    io::Controller controller_;
};
} // namespace snet