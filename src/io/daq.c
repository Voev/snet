#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <snet/io/daq.h>
#include <snet/io/daq_dlt.h>
#include <snet/io/daq_config.h>

static const char* base_api_config_get_input(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_input(cfg);
}

static uint32_t base_api_config_get_msg_pool_size(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_msg_pool_size(cfg);
}

static int base_api_config_get_snaplen(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_snaplen(cfg);
}

static unsigned base_api_config_get_timeout(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_timeout(cfg);
}

static unsigned base_api_config_get_total_instances(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_total_instances(cfg);
}

static unsigned base_api_config_get_instance_id(const SNetIO_DriverConfig_t* modcfg)
{
    SNetIO_BaseConfig_t* cfg = daq_module_config_get_config(modcfg);
    return snet_io_config_get_instance_id(cfg);
}

static void base_api_set_errbuf(SNetIO_DriverController_t* modinst, const char* format, ...)
{
    DAQ_Instance_h instance = modinst->instance;
    va_list ap;
    va_start(ap, format);
    daq_instance_set_errbuf_va(instance, format, ap);
    va_end(ap);
}

void populate_base_api(SNetIO_BaseAPI_t* base_api)
{
    base_api->api_version = DAQ_BASE_API_VERSION;
    base_api->api_size = sizeof(SNetIO_BaseAPI_t);
    base_api->config_get_input = base_api_config_get_input;
    base_api->config_get_snaplen = base_api_config_get_snaplen;
    base_api->config_get_timeout = base_api_config_get_timeout;
    base_api->config_get_msg_pool_size = base_api_config_get_msg_pool_size;
    base_api->config_get_total_instances = base_api_config_get_total_instances;
    base_api->config_get_instance_id = base_api_config_get_instance_id;
    base_api->config_get_mode = snet_io_module_config_get_mode;
    base_api->config_get_variable = snet_io_module_config_get_variable;
    base_api->config_first_variable = snet_io_module_config_first_variable;
    base_api->config_next_variable = snet_io_module_config_next_variable;
    base_api->resolve_subapi = daq_modinst_resolve_subapi;
    base_api->set_errbuf = base_api_set_errbuf;
}

int daq_default_set_filter(void* handle, const char* filter)
{
    (void)handle;
    (void)filter;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_start(void* handle)
{
    (void)handle;
    return DAQ_SUCCESS;
}

int daq_default_inject(void* handle, DAQ_MsgType type, const void* hdr, const uint8_t* data,
                       uint32_t data_len)
{
    (void)handle;
    (void)type;
    (void)hdr;
    (void)data;
    (void)data_len;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_inject_relative(void* handle, SNetIO_Message_t* msg, const uint8_t* data,
                                uint32_t data_len, int reverse)
{
    (void)handle;
    (void)msg;
    (void)data;
    (void)data_len;
    (void)reverse;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_interrupt(void* handle)
{
    (void)handle;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_stop(void* handle)
{
    (void)handle;
    return DAQ_SUCCESS;
}

int daq_default_ioctl(void* handle, DAQ_IoctlCmd cmd, void* arg, size_t arglen)
{
    (void)handle;
    (void)cmd;
    (void)arg;
    (void)arglen;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_stats(void* handle, DAQ_Stats_t* stats)
{
    (void)handle;
    (void)stats;
    return DAQ_ERROR_NOTSUP;
}

void daq_default_reset_stats(void* handle)
{
    (void)handle;
}

int daq_default_get_snaplen(void* handle)
{
    (void)handle;
    return -1;
}

uint32_t daq_default_get_capabilities(void* handle)
{
    (void)handle;
    return 0;
}

int daq_default_get_datalink_type(void* handle)
{
    (void)handle;
    return DLT_NULL;
}

int daq_default_config_load(void* handle, void** new_config)
{
    (void)handle;
    (void)new_config;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_swap(void* handle, void* new_config, void** old_config)
{
    (void)handle;
    (void)new_config;
    (void)old_config;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_free(void* handle, void* old_config)
{
    (void)handle;
    (void)old_config;
    return DAQ_ERROR_NOTSUP;
}

unsigned daq_default_msg_receive(void* handle, const unsigned max_recv,
                                 SNetIO_Message_t* msgs[], DAQ_RecvStatus* rstat)
{
    (void)handle;
    (void)max_recv;
    (void)msgs;
    (void)rstat;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_msg_finalize(void* handle, const SNetIO_Message_t* msg, DAQ_Verdict verdict)
{
    (void)handle;
    (void)msg;
    (void)verdict;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_msg_pool_info(void* handle, DAQ_MsgPoolInfo_t* info)
{
    (void)handle;
    (void)info;
    return DAQ_ERROR_NOTSUP;
}

#define RESOLVE_INSTANCE_API(api, root, fname, dflt)                                               \
    {                                                                                              \
        for (SNetIO_DriverController_t* mi = root; mi; mi = mi->next)                              \
        {                                                                                          \
            if (mi->module->fname)                                                                 \
            {                                                                                      \
                api->fname.func = mi->module->fname;                                               \
                api->fname.context = mi->context;                                                  \
                break;                                                                             \
            }                                                                                      \
        }                                                                                          \
        if (!api->fname.func && dflt)                                                              \
            api->fname.func = daq_default_##fname;                                                 \
    }

void resolve_instance_api(DAQ_InstanceAPI_t* api, SNetIO_DriverController_t* modinst,
                          int default_impl)
{
    memset(api, 0, sizeof(*api));
    RESOLVE_INSTANCE_API(api, modinst, set_filter, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, start, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, inject, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, inject_relative, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, interrupt, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, stop, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, ioctl, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, reset_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_snaplen, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_capabilities, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_datalink_type, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_load, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_swap, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_free, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_receive, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_finalize, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_msg_pool_info, default_impl);
}

int daq_modinst_resolve_subapi(SNetIO_DriverController_t* modinst, DAQ_InstanceAPI_t* api)
{
    if (!modinst->next)
        return DAQ_ERROR_INVAL;

    resolve_instance_api(api, modinst->next, 0);

    return DAQ_SUCCESS;
}

void daq_instance_set_errbuf_va(DAQ_Instance_t* instance, const char* format, va_list ap)
{
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
}

void daq_instance_set_errbuf(DAQ_Instance_t* instance, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
    va_end(ap);
}