#pragma once
#include <snet/tls/types.hpp>

namespace snet::tls {

class ProtocolVersion final {
public:
    using enum VersionCode;

    ProtocolVersion()
        : m_version(0) {
    }

    explicit ProtocolVersion(uint16_t code)
        : m_version(code) {
    }

    /**
     * @param named_version a specific named version of the protocol
     */
    ProtocolVersion(VersionCode named_version)
        : ProtocolVersion(static_cast<uint16_t>(named_version)) {
    }

    /**
     * @param major the major version
     * @param minor the minor version
     */
    ProtocolVersion(uint8_t major, uint8_t minor)
        : ProtocolVersion(static_cast<uint16_t>((static_cast<uint16_t>(major) << 8) | minor)) {
    }

    /**
     * @return major version of the protocol version
     */
    uint8_t major_version() const {
        return static_cast<uint8_t>(m_version >> 8);
    }

    /**
     * @return minor version of the protocol version
     */
    uint8_t minor_version() const {
        return static_cast<uint8_t>(m_version & 0xFF);
    }

    /**
     * @return the version code
     */
    uint16_t version_code() const {
        return m_version;
    }

    /**
     * Generate a human readable version string.
     *
     * for instance "TLS v1.1" or "DTLS v1.0".
     *
     * @return human-readable description of this version
     */
    std::string to_string() const {
        const uint8_t maj = major_version();
        const uint8_t min = minor_version();

        if (maj == 3 && min == 0) {
            return "SSL v3";
        }

        if (maj == 3 && min >= 1) { // TLS v1.x
            return "TLS v1." + std::to_string(min - 1);
        }

        if (maj == 254) { // DTLS 1.x
            return "DTLS v1." + std::to_string(255 - min);
        }

        // Some very new or very old protocol (or bogus data)
        return "Unknown " + std::to_string(maj) + "." + std::to_string(min);
    }

    /**
     * @return if this version is equal to other
     */
    bool operator==(const ProtocolVersion& other) const {
        return (m_version == other.m_version);
    }

    /**
     * @return if this version is not equal to other
     */
    bool operator!=(const ProtocolVersion& other) const {
        return (m_version != other.m_version);
    }

    /**
     * @return if this version is later than other
     */
    bool operator>(const ProtocolVersion& other) const
    {
        return m_version > other.m_version;
    }

    /**
     * @return if this version is later than or equal to other
     */
    bool operator>=(const ProtocolVersion& other) const {
        return (*this == other || *this > other);
    }

    /**
     * @return if this version is earlier to other
     */
    bool operator<(const ProtocolVersion& other) const {
        return !(*this >= other);
    }

    /**
     * @return if this version is earlier than or equal to other
     */
    bool operator<=(const ProtocolVersion& other) const {
        return (*this == other || *this < other);
    }

private:
    uint16_t m_version;
};

} // namespace snet::tls