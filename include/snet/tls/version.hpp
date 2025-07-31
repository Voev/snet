/// @file
/// @brief Declaration of the ProtocolVersion class.

#pragma once
#include <optional>
#include <string_view>
#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Class representing a protocol version.
class ProtocolVersion final
{
public:
    /// @brief Enum representing the version code.
    enum VersionCode : std::uint16_t
    {
        SSLv3_0 = SSL3_VERSION,
        TLSv1_0 = TLS1_VERSION,
        TLSv1_1 = TLS1_1_VERSION,
        TLSv1_2 = TLS1_2_VERSION,
        TLSv1_3 = TLS1_3_VERSION
    };

    /// @brief Default constructor.
    constexpr ProtocolVersion()
        : version_(0)
    {
    }

    /// @brief Destructor.
    ~ProtocolVersion() noexcept = default;

    /// @brief Copy constructor.
    /// @param other The other ProtocolVersion to copy.
    ProtocolVersion(const ProtocolVersion& other) = default;

    /// @brief Move constructor.
    /// @param other The other ProtocolVersion to move.
    ProtocolVersion(ProtocolVersion&& other) noexcept = default;

    /// @brief Copy assignment operator.
    /// @param other The other ProtocolVersion to copy.
    ProtocolVersion& operator=(const ProtocolVersion& other) = default;

    /// @brief Move assignment operator.
    /// @param other The other ProtocolVersion to move.
    ProtocolVersion& operator=(ProtocolVersion&& other) noexcept = default;

    /// @brief Constructor with version code.
    /// @param code The version code.
    explicit constexpr ProtocolVersion(uint16_t code)
        : version_(code)
    {
    }

    /// @brief Constructor with named version.
    /// @param version A specific named version of the protocol.
    constexpr ProtocolVersion(VersionCode version)
        : ProtocolVersion(static_cast<uint16_t>(version))
    {
    }

    /// @brief Constructor with major and minor version.
    /// @param major The major version.
    /// @param minor The minor version.
    constexpr ProtocolVersion(uint8_t major, uint8_t minor)
        : ProtocolVersion(static_cast<uint16_t>((static_cast<uint16_t>(major) << 8) | minor))
    {
    }
    /// @brief Gets the major version of the protocol version.
    /// @return The major version.
    inline uint8_t majorVersion() const noexcept
    {
        return static_cast<uint8_t>(version_ >> 8);
    }

    /// @brief Gets the minor version of the protocol version.
    /// @return The minor version.
    inline uint8_t minorVersion() const noexcept
    {
        return static_cast<uint8_t>(version_ & 0xFF);
    }

    /// @brief Gets the version code.
    /// @return The version code.
    inline uint16_t code() const noexcept
    {
        return version_;
    }

    /// @brief Equality operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is equal to the other, false otherwise.
    inline bool operator==(const ProtocolVersion& other) const noexcept
    {
        return (version_ == other.version_);
    }

    /// @brief Inequality operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is not equal to the other, false otherwise.
    inline bool operator!=(const ProtocolVersion& other) const noexcept
    {
        return (version_ != other.version_);
    }

    /// @brief Greater than operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is later than the other, false otherwise.
    inline bool operator>(const ProtocolVersion& other) const noexcept
    {
        return version_ > other.version_;
    }

    /// @brief Greater than or equal to operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is later than or equal to the other, false otherwise.
    inline bool operator>=(const ProtocolVersion& other) const noexcept
    {
        return (*this == other || *this > other);
    }

    /// @brief Less than operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is earlier than the other, false otherwise.
    inline bool operator<(const ProtocolVersion& other) const noexcept
    {
        return !(*this >= other);
    }

    /// @brief Less than or equal to operator.
    /// @param other The other ProtocolVersion to compare.
    /// @return True if this version is earlier than or equal to the other, false otherwise.
    inline bool operator<=(const ProtocolVersion& other) const noexcept
    {
        return (*this == other || *this < other);
    }

    /// @brief Generates a human-readable version string.
    /// @return A human-readable description of this version.
    std::string toString() const;

    /// @brief Creates a ProtocolVersion from a string.
    /// @param str The string representation of the version.
    /// @return An optional containing the ProtocolVersion if successful, otherwise std::nullopt.
    static std::optional<ProtocolVersion> fromString(std::string_view str);

private:
    uint16_t version_;
};

using ProtocolVersionRange = std::pair<ProtocolVersion, ProtocolVersion>;

/// @brief Parses a protocol version range from a string.
/// @param str The string representation of the version range.
/// @return An optional containing the ProtocolVersionRange if successful, otherwise std::nullopt.
std::optional<ProtocolVersionRange> ParseProtocolVersionRange(std::string_view str);

} // namespace snet::tls