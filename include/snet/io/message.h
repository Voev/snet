#pragma once
#include <stdint.h>
#include <stddef.h>
#include <snet/io/types.h>

/* The DAQ message structure.  Ordered by element size to avoid padding. */
#define DAQ_MSG_META_SLOTS 8
typedef struct snet_io_msg_st
{
    void* hdr;                        /* Pointer to the message header structure for this message */
    uint8_t* data;                    /* Pointer to the variable-length message data (Optional) */
    void* meta[DAQ_MSG_META_SLOTS];   /* Dynamic message metadata slots */
    SNetIO_DriverController_t* owner; /* Handle for the module instance this message belongs to */
    void* priv;        /* Pointer to module instance's private data for this message (Optional) */
    size_t hdr_len;    /* Length of the header structure pointed to by 'hdr' */
    DAQ_MsgType type;  /* Message type (one of DAQ_MsgType or from the user-defined range) */
    uint32_t data_len; /* Length of the data pointed to by 'data'.  Should be 0 if 'data' is NULL */
};

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
