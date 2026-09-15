#pragma once

#include <cstddef>
#include <cstdint>

namespace snet::layers
{

/// @brief TCP flags (RFC 793) — compact 1-byte representation.
///
/// Layout matches the TCP header's flags byte:
///
///   bit:  7   6   5   4   3   2   1   0
///         CWR ECE URG ACK PSH RST SYN FIN
///
/// Only the 6 classic flags (RFC 793) are exposed here. Reserved
/// bits (CWR, ECE) are kept in `raw_` but not interpreted.
class TcpFlags
{
public:
    // Bit masks (RFC 793)
    static constexpr uint8_t FIN = 0x01;
    static constexpr uint8_t SYN = 0x02;
    static constexpr uint8_t RST = 0x04;
    static constexpr uint8_t PSH = 0x08;
    static constexpr uint8_t ACK = 0x10;
    static constexpr uint8_t URG = 0x20;
    // CWR = 0x80, ECE = 0x40 (not exposed)

    constexpr TcpFlags() noexcept = default;

    constexpr TcpFlags(bool fin, bool syn, bool rst, bool psh, bool ack, bool urg) noexcept
        : raw_(static_cast<uint8_t>((fin ? FIN : 0) | (syn ? SYN : 0) | (rst ? RST : 0) | (psh ? PSH : 0) |
                                   (ack ? ACK : 0) | (urg ? URG : 0)))
    {
    }

    static constexpr TcpFlags fromByte(uint8_t b) noexcept
    {
        TcpFlags f;
        f.raw_ = b;
        return f;
    }

    constexpr uint8_t toByte() const noexcept
    {
        return raw_;
    }

    constexpr bool hasFin() const noexcept
    {
        return (raw_ & FIN) != 0;
    }
    constexpr bool hasSyn() const noexcept
    {
        return (raw_ & SYN) != 0;
    }
    constexpr bool hasRst() const noexcept
    {
        return (raw_ & RST) != 0;
    }
    constexpr bool hasPsh() const noexcept
    {
        return (raw_ & PSH) != 0;
    }
    constexpr bool hasAck() const noexcept
    {
        return (raw_ & ACK) != 0;
    }
    constexpr bool hasUrg() const noexcept
    {
        return (raw_ & URG) != 0;
    }

    constexpr TcpFlags& setFin(bool v) noexcept
    {
        setBit(FIN, v);
        return *this;
    }
    constexpr TcpFlags& setSyn(bool v) noexcept
    {
        setBit(SYN, v);
        return *this;
    }
    constexpr TcpFlags& setRst(bool v) noexcept
    {
        setBit(RST, v);
        return *this;
    }
    constexpr TcpFlags& setPsh(bool v) noexcept
    {
        setBit(PSH, v);
        return *this;
    }
    constexpr TcpFlags& setAck(bool v) noexcept
    {
        setBit(ACK, v);
        return *this;
    }
    constexpr TcpFlags& setUrg(bool v) noexcept
    {
        setBit(URG, v);
        return *this;
    }

    constexpr bool isSynOnly() const noexcept
    {
        return hasSyn() && !hasAck();
    }

    constexpr bool isSynAck() const noexcept
    {
        return hasSyn() && hasAck();
    }

    constexpr bool isFinOrRst() const noexcept
    {
        return hasFin() || hasRst();
    }

    constexpr bool isFinRstNoData(size_t payloadLen) const noexcept
    {
        return isFinOrRst() && payloadLen == 0;
    }

    constexpr bool operator==(const TcpFlags& o) const noexcept
    {
        return raw_ == o.raw_;
    }

    constexpr bool operator!=(const TcpFlags& o) const noexcept
    {
        return raw_ != o.raw_;
    }

private:
    constexpr void setBit(uint8_t mask, bool v) noexcept
    {
        raw_ = v ? static_cast<uint8_t>(raw_ | mask) : static_cast<uint8_t>(raw_ & ~mask);
    }

private:
    uint8_t raw_{0};
};

} // namespace snet::layers