#pragma once
#include <memory>
#include <snet/dbus/dynamic_library.hpp>
#include <snet/io/daq.h>

namespace snet::dbus
{

class Driver final
{
public:
    Driver(std::string_view file_path);
    ~Driver() noexcept;

    Driver(const Driver& other) = delete;
    Driver& operator=(const Driver& other) = delete;

    Driver(Driver&& other) noexcept = delete;
    Driver& operator=(Driver&& other) noexcept = delete;

    void reload();

    uint32_t getVersion() const
    {
        return api_->api_version;
    }

    std::string_view getName() const
    {
        return api_->name;
    }

    uint32_t getType() const
    {
        return api_->type;
    }

    int getVariableDescs(const DAQ_VariableDesc_t** var_desc_table)
    {

        if (api_->get_variable_descs)
        {
            return api_->get_variable_descs(var_desc_table);
        }
        else
        {
            *var_desc_table = NULL;
            return 0;
        }
    }

    inline const SNetIO_DriverAPI_t* get() const
    {
        return api_;
    }

private:
    std::string path_;
    SNetIO_DriverAPI_t* api_{nullptr};
    std::unique_ptr<DynamicLibrary> lib_;
};

} // namespace snet::dbus
