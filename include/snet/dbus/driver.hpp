#pragma once
#include <memory>
#include <functional>
#include <snet/dbus/dynamic_library.hpp>
#include <snet/io/daq.h>

namespace snet::dbus
{

class DriverLibrary final
{
public:
    explicit DriverLibrary(std::string path);
    ~DriverLibrary() noexcept;

    DriverLibrary(const DriverLibrary& other) = delete;
    DriverLibrary& operator=(const DriverLibrary& other) = delete;

    DriverLibrary(DriverLibrary&& other) noexcept = delete;
    DriverLibrary& operator=(DriverLibrary&& other) noexcept = delete;

    void reload();

    SNetIO_DriverAPI_t* getDriverAPI();

private:
    std::string path_;
    std::unique_ptr<DynamicLibrary> lib_;
};

} // namespace snet::dbus
