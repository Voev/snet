#include <stdexcept>
#include <cstring>
#include <snet/dbus/controller.hpp>
#include <snet/io/daq_config.h>

namespace snet::dbus
{

Controller::Controller()
{
    std::memset(&instance_, 0, sizeof(instance_));
    state_ = State::Unknown;
}

Controller::~Controller() noexcept
{
}

void Controller::init(DAQ_Config_t* config)
{
    unsigned total_instances = daq_config_get_total_instances(config);
    unsigned instance_id = daq_config_get_instance_id(config);

    if (total_instances && instance_id > total_instances)
    {
        throw std::runtime_error("Can't instantiate with an invalid instance ID!");
    }

    DriverConfig_t* modcfg = daq_config_bottom_module_config(config);
    if (!modcfg)
    {
        throw std::runtime_error("Can't instantiate without a module configuration!");
    }

    state_ = State::Uninitialized;

    /* Build out the instance from the bottom of the configuration stack up. */
    do
    {
        DriverController_t* modinst = new DriverController_t();

        modinst->instance = &instance_;
        modinst->module = daq_module_config_get_module(modcfg);

        /* Push this on top of the module instance stack.  This must be done before instantiating
            the module so that it can be referenced inside of that call. */
        modinst->next = instance_.drivers;
        instance_.drivers = modinst;

        int rval = modinst->module->instantiate(modcfg, modinst, &modinst->context);
        if (rval != DAQ_SUCCESS)
        {
            throw std::runtime_error("failed to instantiate");
        }

        modcfg = daq_config_previous_module_config(config);

    } while (modcfg);

    resolve_instance_api(&instance_.api, instance_.drivers, true);

    state_ = State::Initialized;
}

void Controller::final()
{
    DriverController_t* controller;
    while ((controller = instance_.drivers) != NULL)
    {
        instance_.drivers = controller->next;
        if (controller->context)
            controller->module->destroy(controller->context);
        delete controller;
    }
}

void Controller::setFilter(std::string_view filter)
{
    if (state_ != State::Initialized)
    {
        throw std::runtime_error("Can't set filter on uninitialized instance!");
    }

    int rval = instance_.api.set_filter.func(instance_.api.set_filter.context, filter.data());
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

    int ret = instance_.api.start.func(instance_.api.start.context);
    if (ret == DAQ_SUCCESS)
        state_ = State::Started;
    else
        throw std::runtime_error("failed to start: " + std::string(getError()));
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

    int ret = instance_.api.inject.func(instance_.api.inject.context, type, hdr, data, data_len);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to inject: " + std::string(getError()));
}

void Controller::injectRelative(DAQ_Msg_h msg, const uint8_t* data, uint32_t data_len, int reverse)
{

    if (!msg)
    {
        throw std::invalid_argument("No original message header given!");
    }

    if (!data)
    {
        throw std::invalid_argument("No message data given!");
    }

    int ret = instance_.api.inject_relative.func(instance_.api.inject_relative.context, msg, data,
                                                 data_len, reverse);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to inject relative: " + std::string(getError()));
}

void Controller::interrupt()
{
    int ret = instance_.api.interrupt.func(instance_.api.interrupt.context);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to interrupt: " + std::string(getError()));
}

void Controller::stop()
{
    if (state_ != State::Started)
    {
        throw std::runtime_error("Can't stop an instance that hasn't started!");
    }

    int ret = instance_.api.stop.func(instance_.api.stop.context);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to stop: " + std::string(getError()));
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

    int ret = instance_.api.get_stats.func(instance_.api.get_stats.context, stats);
    if (ret != DAQ_SUCCESS)
        throw std::runtime_error("failed to stop: " + std::string(getError()));
}

void Controller::resetStats()
{
    instance_.api.reset_stats.func(instance_.api.reset_stats.context);
}

int Controller::getSnapLen()
{
    return instance_.api.get_snaplen.func(instance_.api.get_snaplen.context);
}

uint32_t Controller::getCapabilities()
{
    return instance_.api.get_capabilities.func(instance_.api.get_capabilities.context);
}

int Controller::getDataLinkType()
{
    return instance_.api.get_datalink_type.func(instance_.api.get_datalink_type.context);
}

unsigned Controller::receiveMessages(const unsigned max_recv, DAQ_Msg_h msgs[],
                                     DAQ_RecvStatus* rstat)
{
    if (!rstat)
    {
        throw std::invalid_argument("No receive status given to set!");
    }

    if (!msgs)
    {
        *rstat = DAQ_RSTAT_INVALID;
        return 0;
    }

    if (!max_recv)
    {
        *rstat = DAQ_RSTAT_OK;
        return 0;
    }

    return instance_.api.msg_receive.func(instance_.api.msg_receive.context, max_recv, msgs, rstat);
}

void Controller::finalizeMessage(DAQ_Msg_h msg, DAQ_Verdict verdict)
{

    if (!msg)
        throw std::invalid_argument("msg");

    int ret = instance_.api.msg_finalize.func(instance_.api.msg_finalize.context, msg, verdict);
    if (DAQ_SUCCESS != ret)
        throw std::runtime_error("failed to finalize message: " + std::string(getError()));
}

void Controller::getMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
{
    if (!info)
        throw std::invalid_argument("info");

    int ret = instance_.api.get_msg_pool_info.func(instance_.api.get_msg_pool_info.context, info);
    if (DAQ_SUCCESS != ret)
        throw std::runtime_error("failed to get message pool: " + std::string(getError()));
}

} // namespace snet::dbus
