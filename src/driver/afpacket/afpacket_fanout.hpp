#pragma once
#include <cstdint>
#include <linux/if_packet.h>
#include <casket/nonstd/optional.hpp>
#include <casket/nonstd/string_view.hpp>
#include <casket/opt/opt.hpp>

namespace afpacket
{

/// @brief AF_PACKET fanout configuration.
///
/// Combines a load-balancing type (PACKET_FANOUT_*) with optional flags
/// (PACKET_FANOUT_FLAG_*) and a group id, packing them into the 32-bit word
/// expected by setsockopt(SOL_PACKET, PACKET_FANOUT).
///
/// Wire format expected by the kernel:
///   bits  0..15  group id
///   bits 16..23  type  (PACKET_FANOUT_HASH, _LB, _CPU, ...)
///   bits 24..31  flags (PACKET_FANOUT_FLAG_*)
class Fanout final
{
public:
    /// @brief Load-balancing algorithm (PACKET_FANOUT_*).
    enum class Type : uint16_t
    {
        Hash = PACKET_FANOUT_HASH,         ///< Hash of flow -> stable socket.
        LoadBal = PACKET_FANOUT_LB,        ///< Round-robin, may reorder flows.
        Cpu = PACKET_FANOUT_CPU,           ///< Pick socket by CPU.
        Rollover = PACKET_FANOUT_ROLLOVER, ///< Move to next socket on overflow.
        Random = PACKET_FANOUT_RND,        ///< Random pick.
        Qm = PACKET_FANOUT_QM,             ///< Use skb queue_mapping.
    };

    /// @brief Optional flags (PACKET_FANOUT_FLAG_*), 16-bit mask.
    ///        Note: values do NOT fit in uint8_t — highest is 0x8000.
    enum class Flags : uint16_t
    {
        None = 0,
        Rollover = PACKET_FANOUT_FLAG_ROLLOVER, ///< 0x1000
        UniqueId = PACKET_FANOUT_FLAG_UNIQUEID, ///< 0x2000
        Defrag = PACKET_FANOUT_FLAG_DEFRAG,     ///< 0x8000
    };

    Fanout() = default;

    Fanout(Type type, Flags flags = Flags::None, uint16_t id = 0) noexcept
        : type_(type)
        , flags_(flags)
        , id_(id)
        , enabled_(true)
    {
    }

    Type type() const noexcept
    {
        return type_;
    }
    Flags flags() const noexcept
    {
        return flags_;
    }
    uint16_t id() const noexcept
    {
        return id_;
    }
    bool enabled() const noexcept
    {
        return enabled_;
    }

    void setType(Type t) noexcept
    {
        type_ = t;
        enabled_ = true;
    }
    void setFlags(Flags f) noexcept
    {
        flags_ = f;
    }
    void setId(uint16_t id) noexcept
    {
        id_ = id;
    }
    void setEnabled(bool e) noexcept
    {
        enabled_ = e;
    }

    /// @brief Type + flags as the kernel sees them in bits 16..31.
    uint16_t typeFlags() const noexcept
    {
        return static_cast<uint16_t>(type_) | static_cast<uint16_t>(flags_);
    }

    /// @brief Value passed to setsockopt(SOL_PACKET, PACKET_FANOUT).
    ///        Layout: id | (type | flags) << 16.
    uint32_t value() const noexcept
    {
        return uint32_t{id_} | (uint32_t{typeFlags()} << 16);
    }

    static nonstd::optional<Type> typeFromString(nonstd::string_view s) noexcept
    {
        if (s == "hash")
            return Type::Hash;
        if (s == "lb")
            return Type::LoadBal;
        if (s == "cpu")
            return Type::Cpu;
        if (s == "rollover")
            return Type::Rollover;
        if (s == "rnd")
            return Type::Random;
        if (s == "qm")
            return Type::Qm;
        return nonstd::nullopt;
    }

    static nonstd::string_view typeToString(Type t) noexcept
    {
        switch (t)
        {
        case Type::Hash:
            return "hash";
        case Type::LoadBal:
            return "lb";
        case Type::Cpu:
            return "cpu";
        case Type::Rollover:
            return "rollover";
        case Type::Random:
            return "rnd";
        case Type::Qm:
            return "qm";
        }
        return "unknown";
    }

    friend Flags operator|(Flags a, Flags b) noexcept
    {
        return static_cast<Flags>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
    }

    friend Flags& operator|=(Flags& a, Flags b) noexcept
    {
        a = a | b;
        return a;
    }

    friend bool hasFlag(Flags set, Flags bit) noexcept
    {
        return (static_cast<uint16_t>(set) & static_cast<uint16_t>(bit)) != 0;
    }

    static nonstd::optional<Flags> flagsFromString(nonstd::string_view s) noexcept
    {
        if (s.empty())
            return Flags::None;

        Flags result = Flags::None;
        size_t start = 0;

        while (start <= s.size())
        {
            const size_t sep = s.find_first_of("|,", start);
            const size_t end = (sep == nonstd::string_view::npos) ? s.size() : sep;

            auto token = s.substr(start, end - start);
            while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front())))
                token.remove_prefix(1);
            while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back())))
                token.remove_suffix(1);

            if (!token.empty())
            {
                if (token == "none")
                    result = result | Flags::None;
                else if (token == "rollover")
                    result = result | Flags::Rollover;
                else if (token == "uniqueid")
                    result = result | Flags::UniqueId;
                else if (token == "defrag")
                    result = result | Flags::Defrag;
                else
                    return nonstd::nullopt;
            }

            if (sep == nonstd::string_view::npos)
                break;
            start = sep + 1;
        }

        return result;
    }

private:
    Type type_ = Type::Hash;
    Flags flags_ = Flags::None;
    uint16_t id_ = 0;
    bool enabled_ = false;
};

} // namespace afpacket

namespace casket::opt
{

template <>
struct ValueParserImpl<afpacket::Fanout::Type, void>
{
    static afpacket::Fanout::Type parse(nonstd::string_view str)
    {
        auto t = afpacket::Fanout::typeFromString(str);
        if (!t)
        {
            throw RuntimeError("could not parse Fanout::Type value '{}'", str);
        }
        return *t;
    }
};

template <>
struct ValueParserImpl<afpacket::Fanout::Flags, void>
{
    static afpacket::Fanout::Flags parse(nonstd::string_view str)
    {
        auto f = afpacket::Fanout::flagsFromString(str);
        if (!f)
        {
            throw RuntimeError("could not parse Fanout::Flags value '{}'", str);
        }
        return *f;
    }
};

} // namespace casket::opt