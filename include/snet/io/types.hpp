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
    uint64_t hw_packets_received;   /* Packets received by the hardware */
    uint64_t hw_packets_dropped;    /* Packets dropped by the hardware */
    uint64_t packets_received;      /* Packets received by this instance */
    uint64_t packets_filtered;      /* Packets filtered by this instance's BPF */
    uint64_t packets_injected;      /* Packets injected by this instance */
    uint64_t packets_outstanding;   /* Packets outstanding in this instance */
    uint64_t verdicts[MaxVerdicts]; /* Counters of packets handled per-verdict. */
};

struct PacketPoolInfo
{
    uint32_t size;
    uint32_t available;
    size_t memorySize;
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
    Timeout,
    Eof,
    Interrupted,
    Error,
};
