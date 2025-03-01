#include <string.h>
#include <stdlib.h>
#include <snet/io/daq_config.h>

typedef struct snet_io_dict_entry_st
{
    char* key;
    char* value;
    struct snet_io_dict_entry_st* next;
} DAQ_DictEntry_t;

typedef struct snet_io_dict_st
{
    DAQ_DictEntry_t* entries;
    DAQ_DictEntry_t* iterator;
} DAQ_Dict_t;

struct snet_io_driver_config_st
{
    SNetIO_DriverConfig_t* next;
    SNetIO_DriverConfig_t* prev;
    SNetIO_BaseConfig_t* config; /* Backreference to the configuration this is contained within */
    const SNetIO_DriverAPI_t* module; /* Module that will be instantiated with this configuration */
    DAQ_Mode mode;                    /* Module mode (DAQ_MODE_*) */
    DAQ_Dict_t variables;             /* Dictionary of arbitrary key[:value] string pairs */
};

struct snet_io_driver_config_list_st
{
    SNetIO_DriverConfig_t* entries;
    SNetIO_DriverConfig_t* iterator;
};

/*
 * DAQ Dictionary Functions
 */

static int snet_io_dict_insert_entry(DAQ_Dict_t* dict, const char* key, const char* value)
{
    DAQ_DictEntry_t* entry;

    entry = calloc(1, sizeof(DAQ_DictEntry_t));
    if (!entry)
        return DAQ_ERROR_NOMEM;
    entry->key = strdup(key);
    if (!entry->key)
    {
        free(entry);
        return DAQ_ERROR_NOMEM;
    }
    if (value)
    {
        entry->value = strdup(value);
        if (!entry->value)
        {
            free(entry->key);
            free(entry);
            return DAQ_ERROR_NOMEM;
        }
    }
    entry->next = dict->entries;
    dict->entries = entry;

    return DAQ_SUCCESS;
}

static DAQ_DictEntry_t* snet_io_dict_find_entry(DAQ_Dict_t* dict, const char* key)
{
    DAQ_DictEntry_t* entry;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            return entry;
    }

    return NULL;
}

static int snet_io_dict_delete_entry(DAQ_Dict_t* dict, const char* key)
{
    DAQ_DictEntry_t *entry, *prev = NULL;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
        {
            if (prev)
                prev->next = entry->next;
            else
                dict->entries = entry->next;
            free(entry->key);
            free(entry->value);
            free(entry);
            dict->iterator = NULL;
            return 1;
        }
        prev = entry;
    }

    return 0;
}

static void snet_io_dict_clear(DAQ_Dict_t* dict)
{
    DAQ_DictEntry_t* entry;

    while ((entry = dict->entries))
    {
        dict->entries = entry->next;
        free(entry->key);
        free(entry->value);
        free(entry);
    }
    dict->iterator = NULL;
}

static DAQ_DictEntry_t* snet_io_dict_first_entry(DAQ_Dict_t* dict)
{
    dict->iterator = dict->entries;

    return dict->iterator;
}

static DAQ_DictEntry_t* snet_io_dict_next_entry(DAQ_Dict_t* dict)
{
    if (dict->iterator)
        dict->iterator = dict->iterator->next;

    return dict->iterator;
}

/*
 * DAQ Module Configuration Functions
 */


SNetIO_BaseConfig_t* daq_module_config_get_config(const SNetIO_DriverConfig_t* modcfg)
{
    return modcfg->config;
}

DAQ_LINKAGE int snet_io_module_config_new(SNetIO_DriverConfig_t** modcfgptr,
                                          SNetIO_BaseConfig_t* config,
                                          const SNetIO_DriverAPI_t* module)
{
    SNetIO_DriverConfig_t* modcfg;

    if (!modcfgptr || !module)
        return DAQ_ERROR_INVAL;

    modcfg = calloc(1, sizeof(SNetIO_DriverConfig_t));
    if (!modcfg)
        return DAQ_ERROR_NOMEM;

    modcfg->module = module;
    modcfg->config = config;

    *modcfgptr = modcfg;

    return DAQ_SUCCESS;
}

SNetIO_BaseConfig_t* snet_io_module_config_get_config(const SNetIO_DriverConfig_t* modcfg)
{
    return modcfg != NULL ? modcfg->config : NULL;
}

DAQ_LINKAGE const SNetIO_DriverAPI_t*
snet_io_module_config_get_module(const SNetIO_DriverConfig_t* modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->module;
}

DAQ_LINKAGE int snet_io_module_config_set_mode(SNetIO_DriverConfig_t* modcfg, DAQ_Mode mode)
{
    if (!modcfg)
        return DAQ_ERROR_INVAL;

    if ((mode == DAQ_MODE_PASSIVE && !(modcfg->module->type & DAQ_TYPE_INTF_CAPABLE)) ||
        (mode == DAQ_MODE_INLINE && !(modcfg->module->type & DAQ_TYPE_INLINE_CAPABLE)) ||
        (mode == DAQ_MODE_READ_FILE && !(modcfg->module->type & DAQ_TYPE_FILE_CAPABLE)))
        return DAQ_ERROR_INVAL;

    modcfg->mode = mode;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_Mode snet_io_module_config_get_mode(const SNetIO_DriverConfig_t* modcfg)
{
    if (modcfg)
        return modcfg->mode;

    return DAQ_MODE_NONE;
}

DAQ_LINKAGE int snet_io_module_config_set_variable(SNetIO_DriverConfig_t* modcfg, const char* key,
                                                   const char* value)
{
    DAQ_DictEntry_t* entry;
    char* new_value;
    int rval;

    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    entry = snet_io_dict_find_entry(&modcfg->variables, key);
    if (entry)
    {
        if (value)
        {
            new_value = strdup(value);
            if (!new_value)
                return DAQ_ERROR_NOMEM;
            if (entry->value)
                free(entry->value);
            entry->value = new_value;
        }
        else if (entry->value)
        {
            free(entry->value);
            entry->value = NULL;
        }
    }
    else if ((rval = snet_io_dict_insert_entry(&modcfg->variables, key, value)) != DAQ_SUCCESS)
        return rval;
    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char* snet_io_module_config_get_variable(SNetIO_DriverConfig_t* modcfg,
                                                           const char* key)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key)
        return NULL;

    entry = snet_io_dict_find_entry(&modcfg->variables, key);
    if (!entry)
        return NULL;

    return entry->value;
}

DAQ_LINKAGE int snet_io_module_config_delete_variable(SNetIO_DriverConfig_t* modcfg,
                                                      const char* key)
{
    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    if (snet_io_dict_delete_entry(&modcfg->variables, key))
        return DAQ_SUCCESS;

    return DAQ_ERROR;
}

DAQ_LINKAGE int snet_io_module_config_first_variable(SNetIO_DriverConfig_t* modcfg,
                                                     const char** key, const char** value)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = snet_io_dict_first_entry(&modcfg->variables);
    if (entry)
    {
        *key = entry->key;
        *value = entry->value;
    }
    else
    {
        *key = NULL;
        *value = NULL;
    }

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int snet_io_module_config_next_variable(SNetIO_DriverConfig_t* modcfg, const char** key,
                                                    const char** value)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = snet_io_dict_next_entry(&modcfg->variables);
    if (entry)
    {
        *key = entry->key;
        *value = entry->value;
    }
    else
    {
        *key = NULL;
        *value = NULL;
    }
    return DAQ_SUCCESS;
}

DAQ_LINKAGE void snet_io_module_config_clear_variables(SNetIO_DriverConfig_t* modcfg)
{
    if (modcfg != NULL)
    {
        snet_io_dict_clear(&modcfg->variables);
    }
}

DAQ_LINKAGE SNetIO_DriverConfig_t*
snet_io_module_config_get_next(const SNetIO_DriverConfig_t* modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->next;
}

DAQ_LINKAGE void snet_io_module_config_destroy(SNetIO_DriverConfig_t* modcfg)
{
    if (modcfg != NULL)
    {
        snet_io_dict_clear(&modcfg->variables);
        free(modcfg);
    }
}

DAQ_LINKAGE SNetIO_DriverConfigList_t* module_config_list_new()
{
    return calloc(1, sizeof(SNetIO_DriverConfigList_t));
}

DAQ_LINKAGE int module_config_list_push_front(SNetIO_DriverConfigList_t* list,
                                              SNetIO_DriverConfig_t* modcfg)
{
    if (list == NULL || modcfg == NULL)
    {
        return DAQ_ERROR_INVAL;
    }

    if (list->entries == NULL)
    {
        if (modcfg->module->type & DAQ_TYPE_WRAPPER)
            return DAQ_ERROR_INVAL;
    }
    else
    {
        if (!(modcfg->module->type & DAQ_TYPE_WRAPPER))
            return DAQ_ERROR_INVAL;

        list->entries->prev = modcfg;
        modcfg->next = list->entries;
    }

    list->entries = modcfg;
    list->iterator = NULL;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_pop_front(SNetIO_DriverConfigList_t* list)
{
    if (list != NULL && list->entries != NULL)
    {
        SNetIO_DriverConfig_t* modcfg;

        modcfg = list->entries;

        list->entries = modcfg->next;
        list->entries->prev = NULL;
        list->iterator = NULL;

        modcfg->config = NULL;
        modcfg->next = NULL;

        return modcfg;
    }
    return NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_front(SNetIO_DriverConfigList_t* list)
{
    if (list != NULL)
    {
        list->iterator = list->entries;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_back(SNetIO_DriverConfigList_t* list)
{
    if (list == NULL)
        return NULL;

    for (list->iterator = list->entries; list->iterator != NULL && list->iterator->next != NULL;
         list->iterator = list->iterator->next)
        ;

    return list->iterator;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_next(SNetIO_DriverConfigList_t* list)
{
    if (list != NULL && list->iterator != NULL)
    {
        list->iterator = list->iterator->next;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* module_config_list_prev(SNetIO_DriverConfigList_t* list)
{
    if (list != NULL && list->iterator != NULL)
    {
        list->iterator = list->iterator->prev;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE void module_config_list_free(SNetIO_DriverConfigList_t* list)
{
    if (list != NULL)
    {
        SNetIO_DriverConfig_t* modcfg;
        while ((modcfg = list->entries) != NULL)
        {
            list->entries = modcfg->next;
            snet_io_module_config_destroy(modcfg);
        }
        free(list);
    }
}

struct snet_io_base_config_st
{
    char* input;            /* Name of the interface(s) or file to be opened */
    uint32_t msg_pool_size; /* Size of the message pool to create (quantity) */
    int snaplen;            /* Maximum packet capture length */
    unsigned timeout;       /* Read timeout for acquire loop in milliseconds (0 = unlimited) */
    unsigned
        total_instances;  /* Total number of concurrent DAQ instances expected (0 = unspecified) */
    unsigned instance_id; /* ID for the instance to be created (0 = unspecified) */
    SNetIO_DriverConfigList_t* modules;
};

/*
 * DAQ (Top-level) Configuration Functions
 */

DAQ_LINKAGE int snet_io_config_new(SNetIO_BaseConfig_t** cfgptr)
{
    SNetIO_BaseConfig_t* cfg;

    if (!cfgptr)
        return DAQ_ERROR_INVAL;

    cfg = calloc(1, sizeof(SNetIO_BaseConfig_t));
    if (!cfg)
        return DAQ_ERROR_NOMEM;

    cfg->modules = module_config_list_new();

    *cfgptr = cfg;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int snet_io_config_set_input(SNetIO_BaseConfig_t* cfg, const char* input)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    if (cfg->input)
    {
        free(cfg->input);
        cfg->input = NULL;
    }

    if (input)
    {
        cfg->input = strdup(input);
        if (!cfg->input)
            return DAQ_ERROR_NOMEM;
    }

    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char* snet_io_config_get_input(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->input;

    return NULL;
}

DAQ_LINKAGE int snet_io_config_set_msg_pool_size(SNetIO_BaseConfig_t* cfg, uint32_t num_msgs)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->msg_pool_size = num_msgs;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE uint32_t snet_io_config_get_msg_pool_size(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->msg_pool_size;

    return 0;
}

DAQ_LINKAGE int snet_io_config_set_snaplen(SNetIO_BaseConfig_t* cfg, int snaplen)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->snaplen = snaplen;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int snet_io_config_get_snaplen(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->snaplen;

    return 0;
}

DAQ_LINKAGE int snet_io_config_set_timeout(SNetIO_BaseConfig_t* cfg, unsigned timeout)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->timeout = timeout;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned snet_io_config_get_timeout(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->timeout;

    return 0;
}

DAQ_LINKAGE int snet_io_config_set_total_instances(SNetIO_BaseConfig_t* cfg, unsigned total)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->total_instances = total;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned snet_io_config_get_total_instances(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->total_instances;

    return 0;
}

DAQ_LINKAGE int snet_io_config_set_instance_id(SNetIO_BaseConfig_t* cfg, unsigned id)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->instance_id = id;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned snet_io_config_get_instance_id(const SNetIO_BaseConfig_t* cfg)
{
    if (cfg)
        return cfg->instance_id;

    return 0;
}

DAQ_LINKAGE int snet_io_config_push_module_config(SNetIO_BaseConfig_t* cfg,
                                                  SNetIO_DriverConfig_t* modcfg)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    return module_config_list_push_front(cfg->modules, modcfg);
}

DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_pop_module_config(SNetIO_BaseConfig_t* cfg)
{
    if (!cfg)
        return NULL;
    return module_config_list_pop_front(cfg->modules);
}

DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_top_module_config(SNetIO_BaseConfig_t* cfg)
{
    return cfg ? module_config_list_front(cfg->modules) : NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_bottom_module_config(SNetIO_BaseConfig_t* cfg)
{
    return cfg ? module_config_list_back(cfg->modules) : NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_next_module_config(SNetIO_BaseConfig_t* cfg)
{
    return cfg ? module_config_list_next(cfg->modules) : NULL;
}

DAQ_LINKAGE SNetIO_DriverConfig_t* snet_io_config_previous_module_config(SNetIO_BaseConfig_t* cfg)
{
    return cfg ? module_config_list_prev(cfg->modules) : NULL;
}

DAQ_LINKAGE void snet_io_config_destroy(SNetIO_BaseConfig_t* cfg)
{
    if (cfg != NULL)
    {
        module_config_list_free(cfg->modules);
        free(cfg->input);
        free(cfg);
    }
}