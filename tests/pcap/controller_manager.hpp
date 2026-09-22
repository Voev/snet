#pragma once
#include <snet/io.hpp>
#include <casket/utils/singleton.hpp>
#include <casket/opt/opt.hpp>

namespace snet
{

class ControllerManager final : public casket::Singleton<ControllerManager>
{
public:
    ControllerManager()
        : controller_(options_)
    {}

    ~ControllerManager() = default;

    void loadDriver(const io::DriverSpec& config)
    {
        controller_.load(config);
    }

    std::shared_ptr<io::Driver> getDriver(const std::string& name)
    {
        return controller_.get(name);
    }

private:
    casket::opt::ConfigOptions options_;
    snet::io::Controller controller_;
};
} // namespace snet