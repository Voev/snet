#pragma once
#include <optional>
#include <string_view>
#include <snet/tls/types.hpp>

namespace snet::tls {

class ProtocolVersion final {
public:
    using enum VersionCode;

    ProtocolVersion();

    ~ProtocolVersion() noexcept;

    ProtocolVersion(const ProtocolVersion& other);

    ProtocolVersion(ProtocolVersion&& other) noexcept;

    ProtocolVersion& operator=(const ProtocolVersion& other);

    ProtocolVersion& operator=(ProtocolVersion&& other) noexcept;

    explicit ProtocolVersion(uint16_t code);

    /**
     * @param named_version a specific named version of the protocol
     */
    ProtocolVersion(VersionCode version);

    /**
     * @param major the major version
     * @param minor the minor version
     */
    ProtocolVersion(uint8_t major, uint8_t minor);

    /**
     * @return major version of the protocol version
     */
    uint8_t majorVersion() const noexcept;

    /**
     * @return minor version of the protocol version
     */
    uint8_t minorVersion() const noexcept;

    /**
     * @return the version code
     */
    uint16_t code() const noexcept;

    /**
     * Generate a human readable version string.
     *
     * for instance "TLS v1.1" or "DTLS v1.0".
     *
     * @return human-readable description of this version
     */
    std::string toString() const;

    static std::optional<ProtocolVersion> fromString(std::string_view str);

    /**
     * @return if this version is equal to other
     */
    bool operator==(const ProtocolVersion& other) const noexcept;

    /**
     * @return if this version is not equal to other
     */
    bool operator!=(const ProtocolVersion& other) const noexcept;

    /**
     * @return if this version is later than other
     */
    bool operator>(const ProtocolVersion& other) const noexcept;

    /**
     * @return if this version is later than or equal to other
     */
    bool operator>=(const ProtocolVersion& other) const noexcept;

    /**
     * @return if this version is earlier to other
     */
    bool operator<(const ProtocolVersion& other) const noexcept;

    /**
     * @return if this version is earlier than or equal to other
     */
    bool operator<=(const ProtocolVersion& other) const noexcept;

private:
    uint16_t version_;
};

using ProtocolVersionRange = std::pair<ProtocolVersion, ProtocolVersion>;

std::optional<ProtocolVersionRange> ParseProtocolVersionRange(std::string_view str);

} // namespace snet::tls