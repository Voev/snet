#pragma once
#include <snet/io/daq.h>
#include <snet/io/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int daq_module_config_new(DAQ_ModuleConfig_t** modcfgptr, DAQ_Config_t* config, const DriverAPI_t* module);

const DriverAPI_t* daq_module_config_get_module(DAQ_ModuleConfig_t* modcfg);

int daq_module_config_set_mode(DAQ_ModuleConfig_t* modcfg, DAQ_Mode mode);

DAQ_Mode daq_module_config_get_mode(DAQ_ModuleConfig_t* modcfg);

int daq_module_config_set_variable(DAQ_ModuleConfig_t* modcfg, const char* key, const char* value);

const char* daq_module_config_get_variable(DAQ_ModuleConfig_t* modcfg, const char* key);

int daq_module_config_delete_variable(DAQ_ModuleConfig_t* modcfg, const char* key);

int daq_module_config_first_variable(DAQ_ModuleConfig_t* modcfg, const char** key,
                                     const char** value);
int daq_module_config_next_variable(DAQ_ModuleConfig_t* modcfg, const char** key,
                                    const char** value);

void daq_module_config_clear_variables(DAQ_ModuleConfig_t* modcfg);

DAQ_ModuleConfig_t* daq_module_config_get_next(DAQ_ModuleConfig_t* modcfg);

void daq_module_config_destroy(DAQ_ModuleConfig_t* modcfg);

DAQ_LINKAGE DAQ_ModuleConfigList_t* module_config_list_new();

DAQ_LINKAGE void module_config_list_free(DAQ_ModuleConfigList_t* list);

DAQ_LINKAGE int module_config_list_push_front(DAQ_ModuleConfigList_t* list, DAQ_ModuleConfig_t *modcfg);

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_pop_front(DAQ_ModuleConfigList_t* list);

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_front(DAQ_ModuleConfigList_t* list);

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_back(DAQ_ModuleConfigList_t* list);

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_next(DAQ_ModuleConfigList_t* list);

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_prev(DAQ_ModuleConfigList_t* list);

#ifdef __cplusplus
}
#endif