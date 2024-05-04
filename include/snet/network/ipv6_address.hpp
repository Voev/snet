#pragma once
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <system_error>
#include <optional>

namespace snet::network
{

class IPv6Address final
{
public:
    static constexpr std::size_t kBytesCount = 16;
    typedef in6_addr AddrType;
    typedef std::array<std::uint8_t, kBytesCount> BytesType;

    IPv6Address() noexcept
        : addr_()
    {
    }

    ~IPv6Address() = default;

    explicit IPv6Address(const BytesType& bytes) noexcept
    {
        std::memcpy(&addr_.s6_addr, bytes.data(), kBytesCount);
    }

    explicit IPv6Address(const std::uint8_t* bytes, std::size_t length)
    {
        assert(length == kBytesCount);
        std::memcpy(&addr_.s6_addr, bytes, length);
    }

    IPv6Address(const IPv6Address& other) noexcept
        : addr_(other.addr_)
    {
    }

    IPv6Address(IPv6Address&& other) noexcept
        : addr_(other.addr_)
    {
    }

    IPv6Address& operator=(const IPv6Address& other) noexcept
    {
        addr_ = other.addr_;
        return *this;
    }

    IPv6Address& operator=(IPv6Address&& other) noexcept
    {
        addr_ = other.addr_;
        return *this;
    }

    inline std::optional<std::string>
    toString(std::error_code& ec) const noexcept
    {
        if (*this == IPv6Address::any())
        {
            return "any";
        }
        char addrStr[INET6_ADDRSTRLEN];
        const char* addr =
            inet_ntop(AF_INET6, &addr_, addrStr, sizeof(addrStr));
        if (addr == 0)
        {
            ec = std::make_error_code(static_cast<std::errc>(errno));
            return std::nullopt;
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

    inline static std::optional<IPv6Address>
    fromString(const char* str, std::error_code& ec) noexcept
    {
        BytesType bytes;
        if (inet_pton(AF_INET6, str, &bytes) <= 0)
        {
            ec = std::make_error_code(static_cast<std::errc>(errno));
            if (!ec)
                ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv6Address(bytes);
    }

    inline static std::optional<IPv6Address> fromString(const char* str)
    {
        std::error_code ec;
        auto ret = fromString(str, ec);
        if (ec)
            throw ec;
        return ret;
    }

    inline BytesType toBytes() const noexcept
    {
        BytesType bytes;
        std::memcpy(bytes.data(), addr_.s6_addr, kBytesCount);
        return bytes;
    }

    inline static std::optional<IPv6Address>
    fromBytes(const IPv6Address::BytesType& bytes, std::error_code& ec)
    {
        if (bytes.size() != kBytesCount)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv6Address(bytes);
    }

    inline static std::optional<IPv6Address>
    fromBytes(const std::uint8_t* bytes, std::size_t length,
              std::error_code& ec)
    {
        if (length != kBytesCount)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return std::nullopt;
        }
        return IPv6Address(bytes, length);
    }

    inline friend bool operator==(const IPv6Address& a,
                                  const IPv6Address& b) noexcept
    {
        return 0 == std::memcmp(&a.addr_, &b.addr_, sizeof(a.addr_));
    }

    inline friend bool operator!=(const IPv6Address& a,
                                  const IPv6Address& b) noexcept
    {
        return !(a == b);
    }

    inline friend bool operator<(const IPv6Address& a,
                                 const IPv6Address& b) noexcept
    {
        int ret = memcmp(&a.addr_, &b.addr_, sizeof(a.addr_));
        if (ret < 0)
            return true;
        return false;
    }

    inline friend bool operator>(const IPv6Address& a,
                                 const IPv6Address& b) noexcept
    {
        return b < a;
    }

    inline friend bool operator<=(const IPv6Address& a,
                                  const IPv6Address& b) noexcept
    {
        return !(b < a);
    }

    inline friend bool operator>=(const IPv6Address& a,
                                  const IPv6Address& b) noexcept
    {
        return !(a < b);
    }

    static IPv6Address any() noexcept
    {
        return IPv6Address();
    }

private:
    AddrType addr_;
};

} // namespace snet::network

template <> struct std::hash<snet::network::IPv6Address>
{
    std::size_t
    operator()(const snet::network::IPv6Address& addr) const noexcept
    {
        const snet::network::IPv6Address::BytesType bytes = addr.toBytes();
        std::size_t result{0};
        combineBytes(result, &bytes[0]);
        combineBytes(result, &bytes[4]);
        combineBytes(result, &bytes[8]);
        combineBytes(result, &bytes[12]);
        return result;
    }

private:
    static void combineBytes(std::size_t& seed, const unsigned char* bytes)
    {
        const std::size_t bytesHash =
            (static_cast<std::size_t>(bytes[0]) << 24) |
            (static_cast<std::size_t>(bytes[1]) << 16) |
            (static_cast<std::size_t>(bytes[2]) << 8) |
            (static_cast<std::size_t>(bytes[3]));
        seed ^= bytesHash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
};