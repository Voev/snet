#pragma once
#include <snet/layers/layer.hpp>

namespace snet::layers
{

enum class EtherType : uint16_t
{
    IP = 0x0800,           ///< IP protocol version 4
    ARP = 0x0806,          ///< ARP
    ETHBRIDGE = 0x6558,    ///< Transparent Ethernet Bridging
    REVARP = 0x8035,       ///< Reverse ARP
    AT = 0x809B,           ///< AppleTalk protocol
    AARP = 0x80F3,         ///< AppleTalk ARP
    VLAN = 0x8100,         ///< IEEE 802.1Q VLAN tagging
    IPX = 0x8137,          ///< IPX
    IPV6 = 0x86dd,         ///< IP protocol version 6
    LOOPBACK = 0x9000,     ///< Loopback
    PPPOED = 0x8863,       ///< PPPoE discovery
    PPPOES = 0x8864,       ///< PPPoE session
    MPLS = 0x8847,         ///< MPLS
    PPP = 0x880B,          ///< Point-to-point protocol (PPP)
    ROCEV1 = 0x8915,       ///< RDMA over Converged Ethernet (RoCEv1)
    IEEE_802_1AD = 0x88A8, ///< IEEE 802.1ad Provider Bridge, Q-in-Q
    WAKE_ON_LAN = 0x0842,  ///< Wake on LAN
};

#pragma pack(push, 1)
/// @brief Ethernet II header
struct ether_header
{
    uint8_t dstMac[6];  ///< Destination MAC
    uint8_t srcMac[6];  ///< Source MAC
    uint16_t etherType; ///< EtherType
};
#pragma pack(pop)

/// @brief Ethernet II protocol layer
class EthLayer final : public Layer
{
public:
    /// @brief Constructor that creates the layer from an existing packet raw data
    ///
    /// @param[in] data A pointer to the raw data (will be casted to
    /// ether_header)
    /// @param[in] dataLen Size of the data in bytes
    /// @param[in] packet A pointer to the Packet instance where layer will be stored in
    ///
    EthLayer(uint8_t* data, size_t dataLen, Packet* packet)
        : Layer(data, dataLen, nullptr, packet, Ethernet)
    {
    }

    /// @brief Constructor that creates the layer from an existing packet raw data
    ///
    /// @param[in] data A pointer to the raw data (will be casted to
    /// ether_header)
    /// @param[in] dataLen Size of the data in bytes
    /// @param[in] prevLayer A pointer to the previous layer
    /// @param[in] packet A pointer to the Packet instance where layer will be
    ///
    EthLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
        : Layer(data, dataLen, prevLayer, packet, Ethernet)
    {
    }

    ~EthLayer() = default;

    /// @brief Get a pointer to the Ethernet header.
    ///
    /// @return A pointer to the ether_header
    inline ether_header* getEthHeader() const
    {
        return reinterpret_cast<ether_header*>(m_Data);
    }

    /// @brief Parse next layers.
    void parseNextLayer() override;

    /// @brief Get header size.
    ///
    /// @return Size of ether_header.
    size_t getHeaderLen() const override
    {
        return sizeof(ether_header);
    }

    /// @brief Calculate ether_header for known protocols: IPv4, IPv6, ARP, VLAN
    void computeCalculateFields() override;

    std::string toString() const override;

    OsiModelLayer getOsiModelLayer() const override
    {
        return OsiModelDataLinkLayer;
    }

    /// @brief Static method that validates the input data
    ///
    /// @param[in] data The pointer to the beginning of a byte stream of an
    /// Ethernet II packet
    /// @param[in] dataLen The length of the byte stream
    ///
    /// @return true if the data is valid and can represent an Ethernet II packet
    static bool isDataValid(const uint8_t* data, size_t dataLen);
};

} // namespace snet::layers
