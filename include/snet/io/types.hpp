#pragma once
#include <time.h>
#include <cstdint>
#include <cstdlib>
#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/optional.hpp>
#include <casket/opt/opt.hpp>

class Mode
{
public:
    enum Value
    {
        None = 0,
        Passive,
        Inline,
        ReadFile
    };

    Mode() = default;
    constexpr Mode(Value v) noexcept
        : value_(v)
    {
    }

    constexpr operator Value() const noexcept
    {
        return value_;
    }
    explicit operator bool() const = delete;

    constexpr Value value() const noexcept
    {
        return value_;
    }

    static nonstd::optional<Mode> fromString(nonstd::string_view s) noexcept
    {
        if (s == "none")
            return Mode{None};
        if (s == "passive")
            return Mode{Passive};
        if (s == "inline")
            return Mode{Inline};
        if (s == "readfile")
            return Mode{ReadFile};
        return nonstd::nullopt;
    }

    constexpr nonstd::string_view toString() const noexcept
    {
        switch (value_)
        {
        case None:
            return "none";
        case Passive:
            return "passive";
        case Inline:
            return "inline";
        case ReadFile:
            return "readfile";
        }
        return "unknown";
    }

private:
    Value value_ = None;
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

namespace casket::opt
{

template <>
struct ValueParserImpl<Mode, void>
{
    static Mode parse(nonstd::string_view str)
    {
        auto m = Mode::fromString(str);
        if (!m)
        {
            throw RuntimeError("could not parse Mode value '{}'", str);
        }
        return *m;
    }
};

} // namespace casket::opt
