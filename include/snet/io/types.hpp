#pragma once
#include <time.h>
#include <cstdint>
#include <cstdlib>

enum class Mode
{
    None = 0,
    Passive,
    Inline,
    ReadFile
};

enum Verdict
{
    Pass,
    Block,
    Replace,
    Ignore,
    MaxVerdicts
};

struct Stats
{
    uint64_t hwPacketsReceived;     /* Packets received by the hardware */
    uint64_t hwPacketsDropped;      /* Packets dropped by the hardware */
    uint64_t packetsReceived;       /* Packets received by this instance */
    uint64_t packetsFiltered;       /* Packets filtered by this instance's BPF */
    uint64_t packetsInjected;       /* Packets injected by this instance */
    uint64_t packetsOutstanding;    /* Packets outstanding in this instance */
    uint64_t verdicts[MaxVerdicts]; /* Counters of packets handled per-verdict. */
};

enum class Status
{
    Success = 0,
    Error,
    NoMemory,
    NoSuchDevice,
    NotSupported,
    InvalidArgument,
    DeviceAlreadyExists
};

enum class RecvStatus
{
    Ok = 0,
    NoBuffer,
    Timeout,
    Eof,
    Interrupted,
    Error,
    NoMemory,
    WouldBlock
};
