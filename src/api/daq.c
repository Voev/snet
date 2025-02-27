#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <snet/api/daq.h>
#include <snet/api/daq_dlt.h>

typedef struct _daq_dict_entry
{
    char *key;
    char *value;
    struct _daq_dict_entry *next;
} DAQ_DictEntry_t;

typedef struct _daq_dict
{
    DAQ_DictEntry_t *entries;
    DAQ_DictEntry_t *iterator;
} DAQ_Dict_t;

typedef struct _daq_module_config
{
    struct _daq_module_config *next;
    struct _daq_module_config *prev;
    struct _daq_config *config;     /* Backreference to the configuration this is contained within */
    const DAQ_ModuleAPI_t *module;  /* Module that will be instantiated with this configuration */
    DAQ_Mode mode;                  /* Module mode (DAQ_MODE_*) */
    DAQ_Dict_t variables;           /* Dictionary of arbitrary key[:value] string pairs */
} DAQ_ModuleConfig_t;

typedef struct _daq_config
{
    char *input;                    /* Name of the interface(s) or file to be opened */
    uint32_t msg_pool_size;         /* Size of the message pool to create (quantity) */
    int snaplen;                    /* Maximum packet capture length */
    unsigned timeout;               /* Read timeout for acquire loop in milliseconds (0 = unlimited) */
    unsigned total_instances;       /* Total number of concurrent DAQ instances expected (0 = unspecified) */
    unsigned instance_id;           /* ID for the instance to be created (0 = unspecified) */
    DAQ_ModuleConfig_t *module_configs;
    DAQ_ModuleConfig_t *iterator;
} DAQ_Config_t;


/*
 * DAQ Dictionary Functions
 */

static int daq_dict_insert_entry(DAQ_Dict_t *dict, const char *key, const char *value)
{
    DAQ_DictEntry_t *entry;

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

static DAQ_DictEntry_t *daq_dict_find_entry(DAQ_Dict_t *dict, const char *key)
{
    DAQ_DictEntry_t *entry;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            return entry;
    }

    return NULL;
}

static int daq_dict_delete_entry(DAQ_Dict_t *dict, const char *key)
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

static void daq_dict_clear(DAQ_Dict_t *dict)
{
    DAQ_DictEntry_t *entry;

    while ((entry = dict->entries))
    {
        dict->entries = entry->next;
        free(entry->key);
        free(entry->value);
        free(entry);
    }
    dict->iterator = NULL;
}

static DAQ_DictEntry_t *daq_dict_first_entry(DAQ_Dict_t *dict)
{
    dict->iterator = dict->entries;

    return dict->iterator;
}

static DAQ_DictEntry_t *daq_dict_next_entry(DAQ_Dict_t *dict)
{
    if (dict->iterator)
        dict->iterator = dict->iterator->next;

    return dict->iterator;
}


/*
 * DAQ Module Configuration Functions
 */

DAQ_LINKAGE int daq_module_config_new(DAQ_ModuleConfig_t **modcfgptr, const DAQ_ModuleAPI_t *module)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!modcfgptr || !module)
        return DAQ_ERROR_INVAL;

    modcfg = calloc(1, sizeof(DAQ_ModuleConfig_t));
    if (!modcfg)
        return DAQ_ERROR_NOMEM;

    modcfg->module = module;
    *modcfgptr = modcfg;

    return DAQ_SUCCESS;
}

DAQ_Config_t *daq_module_config_get_config(DAQ_ModuleConfig_t *modcfg)
{
    return modcfg->config;
}

DAQ_LINKAGE const DAQ_ModuleAPI_t *daq_module_config_get_module(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->module;
}

DAQ_LINKAGE int daq_module_config_set_mode(DAQ_ModuleConfig_t *modcfg, DAQ_Mode mode)
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

DAQ_LINKAGE DAQ_Mode daq_module_config_get_mode(DAQ_ModuleConfig_t *modcfg)
{
    if (modcfg)
        return modcfg->mode;

    return DAQ_MODE_NONE;
}

DAQ_LINKAGE int daq_module_config_set_variable(DAQ_ModuleConfig_t *modcfg, const char *key, const char *value)
{
    DAQ_DictEntry_t *entry;
    char *new_value;
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

DAQ_LINKAGE const char *daq_module_config_get_variable(DAQ_ModuleConfig_t *modcfg, const char *key)
{
    DAQ_DictEntry_t *entry;

    if (!modcfg || !key)
        return NULL;

    entry = daq_dict_find_entry(&modcfg->variables, key);
    if (!entry)
        return NULL;

    return entry->value;
}

DAQ_LINKAGE int daq_module_config_delete_variable(DAQ_ModuleConfig_t *modcfg, const char *key)
{
    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    if (daq_dict_delete_entry(&modcfg->variables, key))
        return DAQ_SUCCESS;

    return DAQ_ERROR;
}

DAQ_LINKAGE int daq_module_config_first_variable(DAQ_ModuleConfig_t *modcfg, const char **key, const char **value)
{
    DAQ_DictEntry_t *entry;

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

DAQ_LINKAGE int daq_module_config_next_variable(DAQ_ModuleConfig_t *modcfg, const char **key, const char **value)
{
    DAQ_DictEntry_t *entry;

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

DAQ_LINKAGE void daq_module_config_clear_variables(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return;

    daq_dict_clear(&modcfg->variables);
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_module_config_get_next(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->next;
}

DAQ_LINKAGE void daq_module_config_destroy(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return;

    daq_module_config_clear_variables(modcfg);
    free(modcfg);
}


/*
 * DAQ (Top-level) Configuration Functions
 */

DAQ_LINKAGE int daq_config_new(DAQ_Config_t **cfgptr)
{
    DAQ_Config_t *cfg;

    if (!cfgptr)
        return DAQ_ERROR_INVAL;

    cfg = calloc(1, sizeof(DAQ_Config_t));
    if (!cfg)
        return DAQ_ERROR_NOMEM;

    *cfgptr = cfg;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_config_set_input(DAQ_Config_t *cfg, const char *input)
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

DAQ_LINKAGE const char *daq_config_get_input(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->input;

    return NULL;
}

DAQ_LINKAGE int daq_config_set_msg_pool_size(DAQ_Config_t *cfg, uint32_t num_msgs)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->msg_pool_size = num_msgs;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE uint32_t daq_config_get_msg_pool_size(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->msg_pool_size;

    return 0;
}

DAQ_LINKAGE int daq_config_set_snaplen(DAQ_Config_t *cfg, int snaplen)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->snaplen = snaplen;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_config_get_snaplen(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->snaplen;

    return 0;
}

DAQ_LINKAGE int daq_config_set_timeout(DAQ_Config_t *cfg, unsigned timeout)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->timeout = timeout;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_timeout(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->timeout;

    return 0;
}

DAQ_LINKAGE int daq_config_set_total_instances(DAQ_Config_h cfg, unsigned total)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->total_instances = total;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_total_instances(DAQ_Config_h cfg)
{
    if (cfg)
        return cfg->total_instances;

    return 0;
}

DAQ_LINKAGE int daq_config_set_instance_id(DAQ_Config_h cfg, unsigned id)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->instance_id = id;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_instance_id(DAQ_Config_h cfg)
{
    if (cfg)
        return cfg->instance_id;

    return 0;
}

DAQ_LINKAGE int daq_config_push_module_config(DAQ_Config_t *cfg, DAQ_ModuleConfig_t *modcfg)
{
    if (!cfg || !modcfg)
        return DAQ_ERROR_INVAL;

    if (!cfg->module_configs)
    {
        if (modcfg->module->type & DAQ_TYPE_WRAPPER)
            return DAQ_ERROR_INVAL;
    }
    else
    {
        if (!(modcfg->module->type & DAQ_TYPE_WRAPPER))
            return DAQ_ERROR_INVAL;
        cfg->module_configs->prev = modcfg;
        modcfg->next = cfg->module_configs;
    }
    modcfg->config = cfg;
    cfg->module_configs = modcfg;
    cfg->iterator = NULL;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_pop_module_config(DAQ_Config_t *cfg)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!cfg || !cfg->module_configs)
        return NULL;

    modcfg = cfg->module_configs;
    cfg->module_configs = modcfg->next;
    cfg->module_configs->prev = NULL;
    cfg->iterator = NULL;

    modcfg->config = NULL;
    modcfg->next = NULL;

    return modcfg;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_top_module_config(DAQ_Config_t *cfg)
{
    if (!cfg)
        return NULL;

    cfg->iterator = cfg->module_configs;

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_bottom_module_config(DAQ_Config_t *cfg)
{
    if (!cfg)
        return NULL;

    for (cfg->iterator = cfg->module_configs;
         cfg->iterator && cfg->iterator->next;
         cfg->iterator = cfg->iterator->next);

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_next_module_config(DAQ_Config_t *cfg)
{
    if (!cfg || !cfg->iterator)
        return NULL;

    cfg->iterator = cfg->iterator->next;

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_previous_module_config(DAQ_Config_t *cfg)
{
    if (!cfg || !cfg->iterator)
        return NULL;

    cfg->iterator = cfg->iterator->prev;

    return cfg->iterator;
}

DAQ_LINKAGE void daq_config_destroy(DAQ_Config_t *cfg)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!cfg)
        return;

    while ((modcfg = cfg->module_configs) != NULL)
    {
        cfg->module_configs = modcfg->next;
        daq_module_config_destroy(modcfg);
    }
    free(cfg->input);
    free(cfg);
}


static const char *base_api_config_get_input(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_input(cfg);
}

static uint32_t base_api_config_get_msg_pool_size(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_msg_pool_size(cfg);
}

static int base_api_config_get_snaplen(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_snaplen(cfg);
}

static unsigned base_api_config_get_timeout(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_timeout(cfg);
}

static unsigned base_api_config_get_total_instances(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_total_instances(cfg);
}

static unsigned base_api_config_get_instance_id(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_instance_id(cfg);
}

static void base_api_set_errbuf(DAQ_ModuleInstance_h modinst, const char *format, ...)
{
    DAQ_Instance_h instance = modinst->instance;
    va_list ap;
    va_start(ap, format);
    daq_instance_set_errbuf_va(instance, format, ap);
    va_end(ap);
}

void populate_base_api(DAQ_BaseAPI_t *base_api)
{
    base_api->api_version = DAQ_BASE_API_VERSION;
    base_api->api_size = sizeof(DAQ_BaseAPI_t);
    base_api->config_get_input = base_api_config_get_input;
    base_api->config_get_snaplen = base_api_config_get_snaplen;
    base_api->config_get_timeout = base_api_config_get_timeout;
    base_api->config_get_msg_pool_size = base_api_config_get_msg_pool_size;
    base_api->config_get_total_instances = base_api_config_get_total_instances;
    base_api->config_get_instance_id = base_api_config_get_instance_id;
    base_api->config_get_mode = daq_module_config_get_mode;
    base_api->config_get_variable = daq_module_config_get_variable;
    base_api->config_first_variable = daq_module_config_first_variable;
    base_api->config_next_variable = daq_module_config_next_variable;
    base_api->resolve_subapi = daq_modinst_resolve_subapi;
    base_api->set_errbuf = base_api_set_errbuf;
}

int daq_default_set_filter(void *handle, const char *filter)
{
    (void)handle;
    (void)filter;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_start(void *handle)
{
    (void)handle;
    return DAQ_SUCCESS;
}

int daq_default_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    (void)handle;
    (void)type;
    (void)hdr;
    (void)data;
    (void)data_len;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_inject_relative(void *handle, DAQ_Msg_h msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    (void)handle;
    (void)msg;
    (void)data;
    (void)data_len;
    (void)reverse;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_interrupt(void *handle)
{
    (void)handle;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_stop(void *handle)
{
    (void)handle;
    return DAQ_SUCCESS;
}

int daq_default_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    (void)handle;
    (void)cmd;
    (void)arg;
    (void)arglen;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_stats(void *handle, DAQ_Stats_t *stats)
{
    (void)handle;
    (void)stats;
    return DAQ_ERROR_NOTSUP;
}

void daq_default_reset_stats(void *handle)
{
    (void)handle;
}

int daq_default_get_snaplen(void *handle)
{
    (void)handle;
    return -1;
}

uint32_t daq_default_get_capabilities(void *handle)
{
    (void)handle;
    return 0;
}

int daq_default_get_datalink_type(void *handle)
{
    (void)handle;
    return DLT_NULL;
}

int daq_default_config_load(void *handle, void **new_config)
{
    (void)handle;
    (void)new_config;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_swap(void *handle, void *new_config, void **old_config)
{
    (void)handle;
    (void)new_config;
    (void)old_config;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_free(void *handle, void *old_config)
{
    (void)handle;
    (void)old_config;
    return DAQ_ERROR_NOTSUP;
}

unsigned daq_default_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    (void)handle;
    (void)max_recv;
    (void)msgs;
    (void)rstat;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    (void)handle;
    (void)msg;
    (void)verdict;
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    (void)handle;
    (void)info;
    return DAQ_ERROR_NOTSUP;
}

#define RESOLVE_INSTANCE_API(api, root, fname, dflt)    \
{                                                       \
    for (DAQ_ModuleInstance_t *mi = root;               \
         mi;                                            \
         mi = mi->next)                                 \
    {                                                   \
        if (mi->module->fname)                          \
        {                                               \
            api->fname.func = mi->module->fname ;       \
            api->fname.context = mi->context;           \
            break;                                      \
        }                                               \
    }                                                   \
    if (!api->fname.func && dflt)                       \
        api->fname.func = daq_default_ ## fname;        \
}

static void resolve_instance_api(DAQ_InstanceAPI_t *api, DAQ_ModuleInstance_t *modinst, int default_impl)
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

int daq_modinst_resolve_subapi(DAQ_ModuleInstance_t *modinst, DAQ_InstanceAPI_t *api)
{
    if (!modinst->next)
        return DAQ_ERROR_INVAL;

    resolve_instance_api(api, modinst->next, 0);

    return DAQ_SUCCESS;
}

void daq_instance_set_errbuf_va(DAQ_Instance_t *instance, const char *format, va_list ap)
{
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
}

void daq_instance_set_errbuf(DAQ_Instance_t *instance, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
    va_end(ap);
}