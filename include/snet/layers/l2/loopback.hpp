#pragma once
#include <snet/layers/layer.hpp>

namespace snet::layers
{

/** IPv4 protocol **/
#define SNET_BSD_AF_INET 2
/** XEROX NS protocols */
#define SNET_BSD_AF_NS 6
/** ISO */
#define SNET_BSD_AF_ISO 7
/** AppleTalk */
#define SNET_BSD_AF_APPLETALK 16
/** IPX */
#define SNET_BSD_AF_IPX 23
/** OpenBSD (and probably NetBSD), BSD/OS IPv6 */
#define SNET_BSD_AF_INET6_BSD 24
/** FreeBSD IPv6 */
#define SNET_BSD_AF_INET6_FREEBSD 28
/** Darwin IPv6 */
#define SNET_BSD_AF_INET6_DARWIN 30

/// @brief Null/Loopback layer
class NullLoopbackLayer final : public Layer
{
public:
    /// @brief onstructor that creates the layer from an existing packet raw data
    /// @param[in] data A pointer to the raw data
    /// @param[in] dataLen Size of the data in bytes
    /// @param[in] packet A pointer to the Packet instance where layer will be stored in
    NullLoopbackLayer(uint8_t* data, size_t dataLen, Packet* packet)
        : Layer(data, dataLen, nullptr, packet, NULL_LOOPBACK)
    {
    }

    /// @brief Constructor that allocates a new Null/Loopback header
    /// @param[in] family The family protocol to set
    ///
    explicit NullLoopbackLayer(uint32_t family);

    /**
     * A destructor for this layer (does nothing)
     */
    ~NullLoopbackLayer() override = default;

    /// @brief Get protocol family.
    ///
    /// @return Protocol family in this layer.
    uint32_t getFamily() const;

    /// @brief Set a protocol family.
    ///
    /// @param[in] family The family protocol to set.
    void setFamily(uint32_t family);

    void parseNextLayer() override;

    size_t getHeaderLen() const override
    {
        return sizeof(uint32_t);
    }

    void computeCalculateFields() override
    {
    }

    std::string toString() const override;

    OsiModelLayer getOsiModelLayer() const override
    {
        return OsiModelDataLinkLayer;
    }
};

} // namespace snet::layers
