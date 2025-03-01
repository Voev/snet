#pragma once

#define DAQ_PKTHDR_UNKNOWN -1 /* Ingress or Egress not known */
#define DAQ_PKTHDR_FLOOD -2   /* Egress is flooding */
typedef struct _daq_pkt_hdr
{
    struct timeval ts;     /* Timestamp */
    uint32_t pktlen;       /* Original length of this packet (off the wire) */
    int32_t ingress_index; /* Index of the inbound interface. */
    int32_t egress_index;  /* Index of the outbound interface. */
    int16_t ingress_group; /* Index of the inbound group. */
    int16_t egress_group;  /* Index of the outbound group. */
    uint32_t opaque;       /* Opaque context value from the DAQ module or underlying hardware.
                               Directly related to the opaque value in DAQ_FlowStats_t. */
    uint32_t flow_id;      /* Flow ID value provided from the DAQ module or underlying hardware. */
    uint32_t flags;        /* Flags for the packet (DAQ_PKT_FLAG_*) */
    uint32_t address_space_id; /* Unique ID of the address space */
    uint32_t tenant_id;        /* Unique ID of the tenant */
} DAQ_PktHdr_t;

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