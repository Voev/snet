#pragma once

typedef enum
{
    DAQ_MSG_TYPE_PACKET = 1,          /* Packet data */
    DAQ_MSG_TYPE_PAYLOAD,             /* Payload data */
    DAQ_MSG_TYPE_SOF,                 /* Start of Flow statistics */
    DAQ_MSG_TYPE_EOF,                 /* End of Flow statistics */
    DAQ_MSG_TYPE_HA_STATE,            /* HA State blob */
    LAST_BUILTIN_DAQ_MSG_TYPE = 1024, /* End of reserved space for "official" DAQ message types. */
    MAX_DAQ_MSG_TYPE = UINT16_MAX
} DAQ_MsgType;

typedef struct snet_io_driver_api_st SNetIO_DriverAPI_t;
typedef struct snet_io_driver_controller_st SNetIO_DriverController_t;
typedef struct snet_io_driver_config_st SNetIO_DriverConfig_t;
typedef struct snet_io_driver_config_list_st SNetIO_DriverConfigList_t;

typedef struct snet_io_base_config_st SNetIO_BaseConfig_t;

typedef struct snet_io_msg_st SNetIO_Message_t;