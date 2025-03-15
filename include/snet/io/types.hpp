#pragma once
#include <time.h>
#include <cstdint>
#include <cstdlib>

typedef enum
{
    DAQ_MODE_NONE,
    DAQ_MODE_PASSIVE,
    DAQ_MODE_INLINE,
    DAQ_MODE_READ_FILE,
    MAX_DAQ_MODE
} DAQ_Mode;

typedef enum
{
    DAQ_VERDICT_PASS,       /* Pass the packet. */
    DAQ_VERDICT_BLOCK,      /* Block the packet. */
    DAQ_VERDICT_REPLACE,    /* Pass a packet that has been modified in-place. (No resizing allowed!) */
    DAQ_VERDICT_WHITELIST,  /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    DAQ_VERDICT_BLACKLIST,  /* Block the packet and block all future packets in the same flow systemwide. */
    DAQ_VERDICT_IGNORE,     /* Pass the packet and fastpath all future packets in the same flow for this application. */
    MAX_DAQ_VERDICT
} DAQ_Verdict;

typedef struct _daq_stats
{
    uint64_t hw_packets_received;       /* Packets received by the hardware */
    uint64_t hw_packets_dropped;        /* Packets dropped by the hardware */
    uint64_t packets_received;          /* Packets received by this instance */
    uint64_t packets_filtered;          /* Packets filtered by this instance's BPF */
    uint64_t packets_injected;          /* Packets injected by this instance */
    uint64_t packets_outstanding;       /* Packets outstanding in this instance */
    uint64_t verdicts[MAX_DAQ_VERDICT]; /* Counters of packets handled per-verdict. */
} DAQ_Stats_t;

typedef struct _daq_msg_pool_info
{
    uint32_t size;
    uint32_t available;
    size_t mem_size;
} DAQ_MsgPoolInfo_t;



#define DAQ_SUCCESS          0  /* Success! */
#define DAQ_ERROR           -1  /* Generic error */
#define DAQ_ERROR_NOMEM     -2  /* Out of memory error */
#define DAQ_ERROR_NODEV     -3  /* No such device error */
#define DAQ_ERROR_NOTSUP    -4  /* Functionality is unsupported error */
#define DAQ_ERROR_NOMOD     -5  /* No module specified error */
#define DAQ_ERROR_NOCTX     -6  /* No context specified error */
#define DAQ_ERROR_INVAL     -7  /* Invalid argument/request error */
#define DAQ_ERROR_EXISTS    -8  /* Argument or device already exists */
#define DAQ_ERROR_AGAIN     -9  /* Try again */

typedef enum
{
    DAQ_RSTAT_OK = 0,
    DAQ_RSTAT_WOULD_BLOCK,
    DAQ_RSTAT_TIMEOUT,
    DAQ_RSTAT_EOF,
    DAQ_RSTAT_INTERRUPTED,
    DAQ_RSTAT_NOBUF,
    DAQ_RSTAT_ERROR,
    DAQ_RSTAT_INVALID,
    MAX_DAQ_RSTAT
} DAQ_RecvStatus;

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

/* The DAQ message structure.  Ordered by element size to avoid padding. */
#define DAQ_MSG_META_SLOTS 8
typedef struct snet_io_msg_st
{
    void* hdr;                        /* Pointer to the message header structure for this message */
    uint8_t* data;                    /* Pointer to the variable-length message data (Optional) */
    void* meta[DAQ_MSG_META_SLOTS];   /* Dynamic message metadata slots */
    void* priv;        /* Pointer to module instance's private data for this message (Optional) */
    size_t hdr_len;    /* Length of the header structure pointed to by 'hdr' */
    DAQ_MsgType type;  /* Message type (one of DAQ_MsgType or from the user-defined range) */
    uint32_t data_len; /* Length of the data pointed to by 'data'.  Should be 0 if 'data' is NULL */
} SNetIO_Message_t;

/* DAQ Message convenience functions */
static inline DAQ_MsgType daq_msg_get_type(SNetIO_Message_t* msg)
{
    return msg->type;
}

static inline size_t daq_msg_get_hdr_len(SNetIO_Message_t* msg)
{
    return msg->hdr_len;
}

static inline const void* daq_msg_get_hdr(SNetIO_Message_t* msg)
{
    return msg->hdr;
}

static inline const DAQ_PktHdr_t* daq_msg_get_pkthdr(SNetIO_Message_t* msg)
{
    return (const DAQ_PktHdr_t*)msg->hdr;
}

static inline uint32_t daq_msg_get_data_len(SNetIO_Message_t* msg)
{
    return msg->data_len;
}

static inline uint8_t* daq_msg_get_data(SNetIO_Message_t* msg)
{
    return msg->data;
}

static inline const void* daq_msg_get_meta(SNetIO_Message_t* msg, uint8_t slot)
{
    return msg->meta[slot];
}

static inline const void* daq_msg_get_priv_data(SNetIO_Message_t* msg)
{
    return msg->priv;
}
