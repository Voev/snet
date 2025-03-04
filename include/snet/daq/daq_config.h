#pragma once
#include <snet/daq/daq.h>
#include <snet/daq/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int snet_io_module_config_new(SNetIO_DriverConfig_t** modcfgptr, SNetIO_BaseConfig_t* config,
                                  const SNetIO_DriverAPI_t* module);

    const SNetIO_DriverAPI_t* snet_io_module_config_get_module(const SNetIO_DriverConfig_t* modcfg);

    int snet_io_module_config_set_mode(SNetIO_DriverConfig_t* modcfg, DAQ_Mode mode);

    DAQ_Mode snet_io_module_config_get_mode(const SNetIO_DriverConfig_t* modcfg);

    int snet_io_module_config_set_variable(SNetIO_DriverConfig_t* modcfg, const char* key,
                                           const char* value);

    const char* snet_io_module_config_get_variable(SNetIO_DriverConfig_t* modcfg, const char* key);

    int snet_io_module_config_delete_variable(SNetIO_DriverConfig_t* modcfg, const char* key);

    int snet_io_module_config_first_variable(SNetIO_DriverConfig_t* modcfg, const char** key,
                                             const char** value);
    int snet_io_module_config_next_variable(SNetIO_DriverConfig_t* modcfg, const char** key,
                                            const char** value);

    void snet_io_module_config_clear_variables(SNetIO_DriverConfig_t* modcfg);

    SNetIO_DriverConfig_t* snet_io_module_config_get_next(const SNetIO_DriverConfig_t* modcfg);

    void snet_io_module_config_destroy(SNetIO_DriverConfig_t* modcfg);

    DAQ_LINKAGE SNetIO_DriverConfigList_t* module_config_list_new();

    DAQ_LINKAGE void module_config_list_free(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE int module_config_list_push_front(SNetIO_DriverConfigList_t* list,
                                                  SNetIO_DriverConfig_t* modcfg);

    DAQ_LINKAGE SNetIO_DriverConfig_t*
    module_config_list_pop_front(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_front(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_back(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_next(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_prev(SNetIO_DriverConfigList_t* list);

    DAQ_LINKAGE int snet_io_config_new(SNetIO_BaseConfig_t** cfgptr);
    DAQ_LINKAGE int snet_io_config_set_input(SNetIO_BaseConfig_t* cfg, const char* input);
    DAQ_LINKAGE const char* snet_io_config_get_input(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_set_msg_pool_size(SNetIO_BaseConfig_t* cfg, uint32_t num_msgs);
    DAQ_LINKAGE uint32_t snet_io_config_get_msg_pool_size(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_set_snaplen(SNetIO_BaseConfig_t* cfg, int snaplen);
    DAQ_LINKAGE int snet_io_config_get_snaplen(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_set_timeout(SNetIO_BaseConfig_t* cfg, unsigned timeout);
    DAQ_LINKAGE unsigned snet_io_config_get_timeout(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_set_total_instances(SNetIO_BaseConfig_t* cfg, unsigned total);
    DAQ_LINKAGE unsigned snet_io_config_get_total_instances(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_set_instance_id(SNetIO_BaseConfig_t* cfg, unsigned id);
    DAQ_LINKAGE unsigned snet_io_config_get_instance_id(const SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE int snet_io_config_push_module_config(SNetIO_BaseConfig_t* cfg,
                                                      SNetIO_DriverConfig_t* modcfg);
    DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_pop_module_config(SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_top_module_config(SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_bottom_module_config(SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_next_module_config(SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_previous_module_config(SNetIO_BaseConfig_t* cfg);
    DAQ_LINKAGE void snet_io_config_destroy(SNetIO_BaseConfig_t* cfg);

#ifdef __cplusplus
}
#endif