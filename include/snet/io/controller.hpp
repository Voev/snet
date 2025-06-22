#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <snet/io/driver.hpp>
#include <snet/io/driver_config.hpp>
#include <snet/io/config.hpp>


namespace snet::io
{

class Controller final
{
public:
    Controller();

    ~Controller() noexcept;

    std::shared_ptr<Driver> load(const DriverConfig& config);

    std::shared_ptr<Driver> get(const std::string& name);

    void unload(std::shared_ptr<Driver> driver);

private:
    std::unordered_map<std::string, std::shared_ptr<Driver>> drivers_;
};

} // namespace snet::io
