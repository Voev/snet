#include <string.h>
#include <numeric>
#include <typeinfo>
#include <sstream>
#include <ctime>

#include <casket/log/log_manager.hpp>

#include <snet/layers/packet.hpp>

using namespace casket;


namespace snet::layers
{

Packet::Packet()
{
}

Packet::~Packet() noexcept
{
    if (m_DeleteRawDataAtDestructor)
    {
        delete[] m_RawData;
    }
}

Packet::Packet(nonstd::span<const uint8_t> data, bool deleteRawDataAtDestructor, LinkLayerType layerType)
    : m_DeleteRawDataAtDestructor(deleteRawDataAtDestructor)
{
    setRawData(data, layerType, -1);
}

Packet::Packet(size_t maxPacketLen)
    : m_MaxPacketLen(maxPacketLen)
    , m_DeleteRawDataAtDestructor(true)
{
    uint8_t* data = new uint8_t[maxPacketLen];
    memset(data, 0, maxPacketLen);

    setRawData({data, 0}, LINKTYPE_ETHERNET, -1);
}

Packet::Packet(nonstd::span<uint8_t> buffer)
    : m_MaxPacketLen(buffer.size())
{
    setRawData(buffer, LINKTYPE_ETHERNET, -1);
}

bool Packet::setRawData(nonstd::span<const uint8_t> data, LinkLayerType layerType, int frameLength)
{
    if (data.empty() && data.data() == nullptr)
    {
        error("Cannot set null data to packet");
        return false;
    }

    if (frameLength == -1)
    {
        frameLength = data.size();
    }
    else if (frameLength < static_cast<int>(data.size()))
    {
        error("Frame length {} cannot be smaller than data size {}", frameLength, data.size());
        return false;
    }

    if (m_DeleteRawDataAtDestructor && m_RawData)
    {
        delete[] m_RawData;
        m_RawData = nullptr;
    }

    m_FrameLength = frameLength;

    if (m_DeleteRawDataAtDestructor)
    {
        try
        {
            m_RawData = new uint8_t[data.size()];
            std::copy(data.begin(), data.end(), m_RawData);
            m_RawDataLen = data.size();
        }
        catch (const std::bad_alloc&)
        {
            error("Failed to allocate memory for packet data of size {}", data.size());
            m_RawData = nullptr;
            m_RawDataLen = 0;
            return false;
        }
    }
    else
    {
        m_RawData = const_cast<uint8_t*>(data.data());
        m_RawDataLen = data.size();
    }

    m_LinkLayerType = layerType;

    return true;
}

void Packet::clear()
{
    if (m_RawData != nullptr && m_DeleteRawDataAtDestructor)
        delete[] m_RawData;

    m_RawData = nullptr;
    m_RawDataLen = 0;
    m_FrameLength = 0;
}

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

} // namespace snet::layers
