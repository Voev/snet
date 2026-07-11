#include <string.h>
#include <numeric>
#include <typeinfo>
#include <sstream>
#include <ctime>
#include <snet/layers/packet.hpp>

using namespace casket;

namespace snet::layers
{

bool Packet::isLinkTypeValid(int linkTypeValue)
{
    if ((linkTypeValue < 0 || linkTypeValue > 264) && linkTypeValue != 276)
        return false;

    switch (static_cast<LinkLayerType>(linkTypeValue))
    {
    case LINKTYPE_ETHERNET:
    case LINKTYPE_LINUX_SLL:
    case LINKTYPE_RAW:
    case LINKTYPE_DLT_RAW1:
    case LINKTYPE_DLT_RAW2:
    case LINKTYPE_NULL:
    case LINKTYPE_AX25:
    case LINKTYPE_IEEE802_5:
    case LINKTYPE_ARCNET_BSD:
    case LINKTYPE_SLIP:
    case LINKTYPE_PPP:
    case LINKTYPE_FDDI:
    case LINKTYPE_PPP_HDLC:
    case LINKTYPE_PPP_ETHER:
    case LINKTYPE_ATM_RFC1483:
    case LINKTYPE_C_HDLC:
    case LINKTYPE_IEEE802_11:
    case LINKTYPE_FRELAY:
    case LINKTYPE_LOOP:
    case LINKTYPE_LTALK:
    case LINKTYPE_PFLOG:
    case LINKTYPE_IEEE802_11_PRISM:
    case LINKTYPE_IP_OVER_FC:
    case LINKTYPE_SUNATM:
    case LINKTYPE_IEEE802_11_RADIOTAP:
    case LINKTYPE_ARCNET_LINUX:
    case LINKTYPE_APPLE_IP_OVER_IEEE1394:
    case LINKTYPE_MTP2_WITH_PHDR:
    case LINKTYPE_MTP2:
    case LINKTYPE_MTP3:
    case LINKTYPE_SCCP:
    case LINKTYPE_DOCSIS:
    case LINKTYPE_LINUX_IRDA:
    case LINKTYPE_IEEE802_11_AVS:
    case LINKTYPE_BACNET_MS_TP:
    case LINKTYPE_PPP_PPPD:
    case LINKTYPE_GPRS_LLC:
    case LINKTYPE_GPF_T:
    case LINKTYPE_GPF_F:
    case LINKTYPE_LINUX_LAPD:
    case LINKTYPE_BLUETOOTH_HCI_H4:
    case LINKTYPE_USB_LINUX:
    case LINKTYPE_PPI:
    case LINKTYPE_IEEE802_15_4:
    case LINKTYPE_SITA:
    case LINKTYPE_ERF:
    case LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR:
    case LINKTYPE_AX25_KISS:
    case LINKTYPE_LAPD:
    case LINKTYPE_PPP_WITH_DIR:
    case LINKTYPE_C_HDLC_WITH_DIR:
    case LINKTYPE_FRELAY_WITH_DIR:
    case LINKTYPE_IPMB_LINUX:
    case LINKTYPE_IEEE802_15_4_NONASK_PHY:
    case LINKTYPE_USB_LINUX_MMAPPED:
    case LINKTYPE_FC_2:
    case LINKTYPE_FC_2_WITH_FRAME_DELIMS:
    case LINKTYPE_IPNET:
    case LINKTYPE_CAN_SOCKETCAN:
    case LINKTYPE_IPV4:
    case LINKTYPE_IPV6:
    case LINKTYPE_IEEE802_15_4_NOFCS:
    case LINKTYPE_DBUS:
    case LINKTYPE_DVB_CI:
    case LINKTYPE_MUX27010:
    case LINKTYPE_STANAG_5066_D_PDU:
    case LINKTYPE_NFLOG:
    case LINKTYPE_NETANALYZER:
    case LINKTYPE_NETANALYZER_TRANSPARENT:
    case LINKTYPE_IPOIB:
    case LINKTYPE_MPEG_2_TS:
    case LINKTYPE_NG40:
    case LINKTYPE_NFC_LLCP:
    case LINKTYPE_INFINIBAND:
    case LINKTYPE_SCTP:
    case LINKTYPE_USBPCAP:
    case LINKTYPE_RTAC_SERIAL:
    case LINKTYPE_BLUETOOTH_LE_LL:
    case LINKTYPE_NETLINK:
    case LINKTYPE_BLUETOOTH_LINUX_MONITOR:
    case LINKTYPE_BLUETOOTH_BREDR_BB:
    case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
    case LINKTYPE_PROFIBUS_DL:
    case LINKTYPE_PKTAP:
    case LINKTYPE_EPON:
    case LINKTYPE_IPMI_HPM_2:
    case LINKTYPE_ZWAVE_R1_R2:
    case LINKTYPE_ZWAVE_R3:
    case LINKTYPE_WATTSTOPPER_DLM:
    case LINKTYPE_ISO_14443:
    case LINKTYPE_LINUX_SLL2:
        return true;
    default:
        return false;
    }
}

nonstd::optional<LayerInfo> Packet::parseLayer(ProtocolType protocol, size_t globalOffset, size_t remaining) noexcept
{
    LayerInfo info{};
    info.protocol = protocol;
    info.offset = globalOffset;
    info.payloadOffset = 0;

    switch (protocol)
    {
    case Ethernet:
    {
        constexpr size_t ETHERNET_LEN = 14;
        if (remaining < ETHERNET_LEN)
        {
            return nonstd::nullopt;
        }

        info.headerLength = ETHERNET_LEN;
        info.payloadOffset = globalOffset + ETHERNET_LEN;

        auto eth = EthernetHeader();
        if (!eth.initialize(info, *this))
        {
            return nonstd::nullopt;
        }

        if (eth.etherType() == EtherType::VLAN || eth.etherType() == EtherType::IEEE_802_1AD)
        {
            if (remaining >= ETHERNET_LEN + 4)
            {
                info.headerLength = ETHERNET_LEN + 4;
                info.payloadOffset = globalOffset + ETHERNET_LEN + 4;
            }
        }
        break;
    }

    case IPv4:
    {
        constexpr size_t MIN_IP_LEN = 20;
        if (remaining < MIN_IP_LEN)
        {
            return nonstd::nullopt;
        }

        auto ip = IPv4Header();
        if (!ip.initialize(info, *this))
        {
            return nonstd::nullopt;
        }

        info.headerLength = ip.headerLength();
        info.payloadOffset = globalOffset + info.headerLength;
        break;
    }

    case IPv6:
    {
        constexpr size_t IPV6_LEN = 40;
        if (remaining < IPV6_LEN)
        {
            return nonstd::nullopt;
        }

        info.headerLength = IPV6_LEN;
        info.payloadOffset = globalOffset + IPV6_LEN;
        break;
    }

    case TCP:
    {
        constexpr size_t MIN_TCP_LEN = 20;
        if (remaining < MIN_TCP_LEN)
        {
            return nonstd::nullopt;
        }

        TCPHeader tcp;
        if (!tcp.initialize(info, *this))
        {
            return nonstd::nullopt;
        }

        info.headerLength = tcp.headerLength();
        info.payloadOffset = globalOffset + info.headerLength;
        break;
    }

    default:
        info.headerLength = remaining;
        info.payloadOffset = globalOffset + remaining;
        break;
    }

    if (globalOffset + info.headerLength > rawDataLen_)
    {
        return nonstd::nullopt;
    }

    return info;
}

void Packet::parse() noexcept
{
    layerCount_ = 0;

    size_t packetLen = rawDataLen_;
    size_t offset = 0;

    ProtocolType currentProto = getProtocolFromLinkType(linkLayerType_);

    while (offset < packetLen && layerCount_ < layers_.max_size())
    {
        size_t remaining = packetLen - offset;

        auto layerInfo = parseLayer(currentProto, offset, remaining);
        if (!layerInfo)
        {
            break;
        }

        layers_[layerCount_++] = *layerInfo;
        offset = layerInfo->getEndOffset();

        if (offset >= packetLen)
        {
            break;
        }

        const LayerInfo& currentLayer = layers_[layerCount_ - 1];
        currentProto = getNextProtocol(currentLayer);

        if (currentProto == UnknownProtocol)
        {
            break;
        }
    }
}

} // namespace snet::layers