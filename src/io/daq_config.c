#include <string.h>
#include <stdlib.h>
#include <snet/io/daq_config.h>

typedef struct daq_dict_entry_st
{
    char* key;
    char* value;
    struct daq_dict_entry_st* next;
} DAQ_DictEntry_t;

typedef struct _daq_dict
{
    DAQ_DictEntry_t* entries;
    DAQ_DictEntry_t* iterator;
} DAQ_Dict_t;

struct daq_module_config_st
{
    DAQ_ModuleConfig_t* next;
    DAQ_ModuleConfig_t* prev;
    DAQ_Config_t* config;          /* Backreference to the configuration this is contained within */
    const DriverAPI_t* module; /* Module that will be instantiated with this configuration */
    DAQ_Mode mode;                 /* Module mode (DAQ_MODE_*) */
    DAQ_Dict_t variables;          /* Dictionary of arbitrary key[:value] string pairs */
};

struct daq_module_config_list_st
{
    DAQ_ModuleConfig_t* entries;
    DAQ_ModuleConfig_t* iterator;
};

/*
 * DAQ Dictionary Functions
 */

static int daq_dict_insert_entry(DAQ_Dict_t* dict, const char* key, const char* value)
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

static DAQ_DictEntry_t* daq_dict_find_entry(DAQ_Dict_t* dict, const char* key)
{
    DAQ_DictEntry_t* entry;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            return entry;
    }

    return NULL;
}

static int daq_dict_delete_entry(DAQ_Dict_t* dict, const char* key)
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

static void daq_dict_clear(DAQ_Dict_t* dict)
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

static DAQ_DictEntry_t* daq_dict_first_entry(DAQ_Dict_t* dict)
{
    dict->iterator = dict->entries;

    return dict->iterator;
}

static DAQ_DictEntry_t* daq_dict_next_entry(DAQ_Dict_t* dict)
{
    if (dict->iterator)
        dict->iterator = dict->iterator->next;

    return dict->iterator;
}

/*
 * DAQ Module Configuration Functions
 */

DAQ_LINKAGE int daq_module_config_new(DAQ_ModuleConfig_t** modcfgptr, DAQ_Config_t* config, const DriverAPI_t* module)
{
    DAQ_ModuleConfig_t* modcfg;

    if (!modcfgptr || !module)
        return DAQ_ERROR_INVAL;

    modcfg = calloc(1, sizeof(DAQ_ModuleConfig_t));
    if (!modcfg)
        return DAQ_ERROR_NOMEM;

    modcfg->module = module;
    modcfg->config = config;

    *modcfgptr = modcfg;

    return DAQ_SUCCESS;
}

DAQ_Config_t* daq_module_config_get_config(DAQ_ModuleConfig_t* modcfg)
{
    return modcfg ? modcfg->config : NULL;
}

DAQ_LINKAGE const DriverAPI_t* daq_module_config_get_module(DAQ_ModuleConfig_t* modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->module;
}

DAQ_LINKAGE int daq_module_config_set_mode(DAQ_ModuleConfig_t* modcfg, DAQ_Mode mode)
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

DAQ_LINKAGE DAQ_Mode daq_module_config_get_mode(DAQ_ModuleConfig_t* modcfg)
{
    if (modcfg)
        return modcfg->mode;

    return DAQ_MODE_NONE;
}

DAQ_LINKAGE int daq_module_config_set_variable(DAQ_ModuleConfig_t* modcfg, const char* key,
                                               const char* value)
{
    DAQ_DictEntry_t* entry;
    char* new_value;
    int rval;

    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_find_entry(&modcfg->variables, key);
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
    else if ((rval = daq_dict_insert_entry(&modcfg->variables, key, value)) != DAQ_SUCCESS)
        return rval;
    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char* daq_module_config_get_variable(DAQ_ModuleConfig_t* modcfg, const char* key)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key)
        return NULL;

    entry = daq_dict_find_entry(&modcfg->variables, key);
    if (!entry)
        return NULL;

    return entry->value;
}

DAQ_LINKAGE int daq_module_config_delete_variable(DAQ_ModuleConfig_t* modcfg, const char* key)
{
    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    if (daq_dict_delete_entry(&modcfg->variables, key))
        return DAQ_SUCCESS;

    return DAQ_ERROR;
}

DAQ_LINKAGE int daq_module_config_first_variable(DAQ_ModuleConfig_t* modcfg, const char** key,
                                                 const char** value)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_first_entry(&modcfg->variables);
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

DAQ_LINKAGE int daq_module_config_next_variable(DAQ_ModuleConfig_t* modcfg, const char** key,
                                                const char** value)
{
    DAQ_DictEntry_t* entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_next_entry(&modcfg->variables);
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

DAQ_LINKAGE void daq_module_config_clear_variables(DAQ_ModuleConfig_t* modcfg)
{
    if (modcfg != NULL)
    {
        daq_dict_clear(&modcfg->variables);
    }
}

DAQ_LINKAGE DAQ_ModuleConfig_t* daq_module_config_get_next(DAQ_ModuleConfig_t* modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->next;
}

DAQ_LINKAGE void daq_module_config_destroy(DAQ_ModuleConfig_t* modcfg)
{
    if (modcfg != NULL)
    {
        daq_dict_clear(&modcfg->variables);
        free(modcfg);
    }
}

DAQ_LINKAGE DAQ_ModuleConfigList_t* module_config_list_new()
{
    return calloc(1, sizeof(DAQ_ModuleConfigList_t));
}

DAQ_LINKAGE int module_config_list_push_front(DAQ_ModuleConfigList_t* list, DAQ_ModuleConfig_t *modcfg)
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

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_pop_front(DAQ_ModuleConfigList_t* list)
{
    if (list != NULL && list->entries != NULL)
    {
        DAQ_ModuleConfig_t* modcfg;

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

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_front(DAQ_ModuleConfigList_t* list)
{
    if (list != NULL)
    {
        list->iterator = list->entries;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_back(DAQ_ModuleConfigList_t* list)
{
    if (list == NULL)
        return NULL;

    for (list->iterator = list->entries; list->iterator != NULL && list->iterator->next != NULL;
         list->iterator = list->iterator->next)
        ;

    return list->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_next(DAQ_ModuleConfigList_t* list)
{
    if (list != NULL && list->iterator != NULL)
    {
        list->iterator = list->iterator->next;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE DAQ_ModuleConfig_t* module_config_list_prev(DAQ_ModuleConfigList_t* list)
{
    if (list != NULL && list->iterator != NULL)
    {
        list->iterator = list->iterator->prev;
        return list->iterator;
    }
    return NULL;
}

DAQ_LINKAGE void module_config_list_free(DAQ_ModuleConfigList_t* list)
{
    if (list != NULL)
    {
        DAQ_ModuleConfig_t* modcfg;
        while ((modcfg = list->entries) != NULL)
        {
            list->entries = modcfg->next;
            daq_module_config_destroy(modcfg);
        }
        free(list);
    }
}