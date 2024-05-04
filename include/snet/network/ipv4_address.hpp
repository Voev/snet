#pragma once
#include <cassert>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <system_error>
#include <optional>

namespace snet::network
{

class IPv4Address final
{
public:
    static constexpr std::size_t kBytesCount = 4;
    typedef in_addr AddrType;
    typedef std::uint32_t UintType;
    typedef std::array<std::uint8_t, kBytesCount> BytesType;

    IPv4Address() noexcept
    {
        addr_.s_addr = 0;
    }

    ~IPv4Address() = default;

    explicit IPv4Address(UintType addr) noexcept
    {
        addr_.s_addr = htonl(addr);
    }

    explicit IPv4Address(const BytesType& bytes)
    {
        assert(bytes.size() == kBytesCount);
        std::memcpy(&addr_.s_addr, bytes.data(), kBytesCount);
    }

    explicit IPv4Address(const std::uint8_t* bytes, std::size_t length)
    {
        assert(length == kBytesCount);
        std::memcpy(&addr_.s_addr, bytes, length);
    }

    IPv4Address(const IPv4Address& other) noexcept
        : addr_(other.addr_)
    {
    }

    IPv4Address(IPv4Address&& other) noexcept
        : addr_(other.addr_)
    {
    }

    IPv4Address& operator=(const IPv4Address& other) noexcept
    {
        addr_ = other.addr_;
        return *this;
    }

    IPv4Address& operator=(IPv4Address&& other) noexcept
    {
        addr_ = other.addr_;
        return *this;
    }

    inline UintType toUint() const
    {
        return ntohl(addr_.s_addr);
    }

    inline BytesType toBytes() const noexcept
    {
        BytesType bytes;
        std::memcpy(bytes.data(), &addr_.s_addr, kBytesCount);
        return bytes;
    }

    inline std::optional<std::string> toString(std::error_code& ec) const noexcept
    {
        if (*this == IPv4Address::any())
        {
            return "any";
        }
        char addrStr[INET_ADDRSTRLEN];
        const char* addr = inet_ntop(AF_INET, &addr_, addrStr, sizeof(addrStr));
        if (addr == 0)
        {
            ec = std::make_error_code(static_cast<std::errc>(errno));
            return std::string();
        }
        return addr;
    }

    inline std::optional<std::string> toString() const
    {
        std::error_code ec;
        auto ret = toString(ec);
        if (ec)
            throw ec;
        return ret;
    }

    inline static std::optional<IPv4Address> fromString(const char* str,
                                         std::error_code& ec) noexcept
    {
        BytesType bytes;
        if (inet_pton(AF_INET, str, &bytes) <= 0)
        {
            ec = std::make_error_code(static_cast<std::errc>(errno));
            if (!ec)
                ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv4Address(bytes);
    }

    inline static std::optional<IPv4Address> fromString(const char* str)
    {
        std::error_code ec;
        auto ret = fromString(str, ec);
        if (ec)
            throw ec;
        return ret;
    }

    inline static std::optional<IPv4Address> fromBytes(const IPv4Address::BytesType& bytes, std::error_code& ec)
    {
        if (bytes.size() != kBytesCount)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv4Address(bytes);
    }

    inline static std::optional<IPv4Address>
    fromBytes(const std::uint8_t* bytes, std::size_t length,
              std::error_code& ec)
    {
        if (length != kBytesCount)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv4Address(bytes, length);
    }

    inline friend bool operator==(const IPv4Address& a,
                                  const IPv4Address& b) noexcept
    {
        return a.toUint() == b.toUint();
    }

    inline friend bool operator!=(const IPv4Address& a,
                                  const IPv4Address& b) noexcept
    {
        return a.toUint() != b.toUint();
    }

    inline friend bool operator<(const IPv4Address& a,
                                 const IPv4Address& b) noexcept
    {
        return a.toUint() < b.toUint();
    }

    inline friend bool operator>(const IPv4Address& a,
                                 const IPv4Address& b) noexcept
    {
        return a.toUint() > b.toUint();
    }

    inline friend bool operator<=(const IPv4Address& a,
                                  const IPv4Address& b) noexcept
    {
        return a.toUint() <= b.toUint();
    }

    inline friend bool operator>=(const IPv4Address& a,
                                  const IPv4Address& b) noexcept
    {
        return a.toUint() >= b.toUint();
    }

    inline static IPv4Address any() noexcept
    {
        return IPv4Address();
    }

private:
    AddrType addr_;
};

} // namespace snet::network

template <> struct std::hash<snet::network::IPv4Address>
{
    std::size_t operator()(const snet::network::IPv4Address& addr) const noexcept
    {
        return std::hash<std::uint32_t>()(addr.toUint());
    }
};
