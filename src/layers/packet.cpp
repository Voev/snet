#include <string.h>
#include <numeric>
#include <typeinfo>
#include <sstream>
#include <ctime>

#include <casket/log/log_manager.hpp>

#include <snet/layers/packet.hpp>
#include <snet/layers/l2/eth_layer.hpp>
#include <snet/layers/l2/loopback.hpp>
#include <snet/layers/l3/ipv4_layer.hpp>
#include <snet/layers/l3/ipv6_layer.hpp>
#include <snet/layers/payload_layer.hpp>

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
    , m_CanReallocateData(true)
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

void Packet::parsePacket(ProtocolTypeFamily parseUntil, OsiModelLayer parseUntilLayer)
{
    destructPacketData();

    m_FirstLayer = nullptr;
    m_LastLayer = nullptr;
    m_MaxPacketLen = m_RawDataLen;
    m_CanReallocateData = true;

    m_FirstLayer = createFirstLayer(m_LinkLayerType);

    m_LastLayer = m_FirstLayer;
    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr && (parseUntil == UnknownProtocol || !curLayer->isMemberOfProtocolFamily(parseUntil)) &&
           curLayer->getOsiModelLayer() <= parseUntilLayer)
    {
        curLayer->parseNextLayer();
        curLayer->m_IsAllocatedInPacket = true;
        curLayer = curLayer->getNextLayer();
        if (curLayer != nullptr)
            m_LastLayer = curLayer;
    }

    if (curLayer != nullptr && curLayer->isMemberOfProtocolFamily(parseUntil))
    {
        curLayer->m_IsAllocatedInPacket = true;
    }

    if (curLayer != nullptr && curLayer->getOsiModelLayer() > parseUntilLayer)
    {
        // don't delete the first layer. If already past the target layer, treat
        // the same as if the layer was found.
        if (curLayer == m_FirstLayer)
        {
            curLayer->m_IsAllocatedInPacket = true;
        }
        else
        {
            m_LastLayer = curLayer->getPrevLayer();
            delete curLayer;
            m_LastLayer->m_NextLayer = nullptr;
        }
    }
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

void Packet::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
    memcpy((uint8_t*)m_RawData + m_RawDataLen, dataToAppend, dataToAppendLen);
    m_RawDataLen += dataToAppendLen;
    m_FrameLength = m_RawDataLen;
}

void Packet::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
    // memmove copies data as if there was an intermediate buffer in between -
    // so it allows for copying processes on overlapping src/dest ptrs if
    // insertData is called with atIndex == m_RawDataLen, then no data is being
    // moved. The data of the raw packet is still extended by dataToInsertLen
    memmove((uint8_t*)m_RawData + atIndex + dataToInsertLen, (uint8_t*)m_RawData + atIndex, m_RawDataLen - atIndex);

    if (dataToInsert != nullptr)
    {
        // insert data
        memcpy((uint8_t*)m_RawData + atIndex, dataToInsert, dataToInsertLen);
    }

    m_RawDataLen += dataToInsertLen;
    m_FrameLength = m_RawDataLen;
}

bool Packet::reallocateData(size_t newBufferLength)
{
    if (newBufferLength == m_RawDataLen)
        return true;

    if (newBufferLength < m_RawDataLen)
    {
        return false;
    }

    uint8_t* newBuffer = new uint8_t[newBufferLength];
    memset(newBuffer, 0, newBufferLength);
    memcpy(newBuffer, m_RawData, m_RawDataLen);
    if (m_DeleteRawDataAtDestructor)
        delete[] m_RawData;

    m_DeleteRawDataAtDestructor = true;
    m_RawData = newBuffer;

    return true;
}

bool Packet::removeData(size_t atIndex, size_t numOfBytesToRemove)
{
    if ((atIndex + numOfBytesToRemove) > m_RawDataLen)
    {
        return false;
    }

    // only move data if we are removing data somewhere in the layer, not at the
    // end of the last layer this is so that resizing of the last layer can
    // occur fast by just reducing the fictional length of the packet
    // (m_RawDataLen) by the given amount
    if ((atIndex + numOfBytesToRemove) != m_RawDataLen)
        // memmove copies data as if there was an intermediate buffer in between
        // - so it allows for copying processes on overlapping src/dest ptrs
        memmove((uint8_t*)m_RawData + atIndex, (uint8_t*)m_RawData + atIndex + numOfBytesToRemove,
                m_RawDataLen - (atIndex + numOfBytesToRemove));

    m_RawDataLen -= numOfBytesToRemove;
    m_FrameLength = m_RawDataLen;
    return true;
}

void Packet::destructPacketData()
{
    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr)
    {
        Layer* nextLayer = curLayer->getNextLayer();
        if (curLayer->m_IsAllocatedInPacket)
            delete curLayer;
        curLayer = nextLayer;
    }
}

void Packet::reallocateRawData(size_t newSize)
{
    debug("Allocating packet to new size: {}", newSize);

    // allocate a new array with size newSize
    m_MaxPacketLen = newSize;

    // set the new array to RawPacket
    if (!reallocateData(m_MaxPacketLen))
    {
        error("Couldn't reallocate data of raw packet to {} bytes", m_MaxPacketLen);
        return;
    }

    // set all data pointers in layers to the new array address
    const uint8_t* dataPtr = m_RawData;

    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr)
    {
        debug("Setting new data pointer to layer '{}'", typeid(curLayer).name());
        curLayer->m_Data = (uint8_t*)dataPtr;
        dataPtr += curLayer->getHeaderLen();
        curLayer = curLayer->getNextLayer();
    }
}

Layer* Packet::getLayerOfType(ProtocolType layerType, int index) const
{
    Layer* curLayer = getFirstLayer();
    int curIndex = 0;
    while (curLayer != nullptr)
    {
        if (curLayer->getProtocol() == layerType)
        {
            if (curIndex < index)
                curIndex++;
            else
                break;
        }
        curLayer = curLayer->getNextLayer();
    }

    return curLayer;
}

bool Packet::isPacketOfType(ProtocolType protocolType) const
{
    Layer* curLayer = getFirstLayer();
    while (curLayer != nullptr)
    {
        if (curLayer->getProtocol() == protocolType)
        {
            return true;
        }
        curLayer = curLayer->getNextLayer();
    }

    return false;
}

bool Packet::isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const
{
    Layer* curLayer = getFirstLayer();
    while (curLayer != nullptr)
    {
        if (curLayer->isMemberOfProtocolFamily(protocolTypeFamily))
        {
            return true;
        }
        curLayer = curLayer->getNextLayer();
    }

    return false;
}

bool Packet::extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend)
{
    if (layer == nullptr)
    {
        error("Layer is nullptr");
        return false;
    }

    // verify layer is allocated to this packet
    if (!(layer->m_Packet == this))
    {
        error("Layer isn't allocated to this packet");
        return false;
    }

    if (m_RawDataLen + numOfBytesToExtend > m_MaxPacketLen)
    {
        if (!m_CanReallocateData)
        {
            error("With the layer extended size the packet will "
                  "exceed the size of the pre-allocated buffer: {} bytes",
                  m_MaxPacketLen);
            return false;
        }
        // reallocate to maximum value of: twice the max size of the packet or
        // max size + new required length
        if (m_RawDataLen + numOfBytesToExtend > m_MaxPacketLen * 2)
            reallocateRawData(m_RawDataLen + numOfBytesToExtend + m_MaxPacketLen);
        else
            reallocateRawData(m_MaxPacketLen * 2);
    }

    // insert layer data to raw packet
    int indexToInsertData = layer->m_Data + offsetInLayer - m_RawData;
    // passing nullptr to insertData will move the data by numOfBytesToExtend
    // no new data has to be created for this insertion which saves at least
    // little time this move operation occurs on already allocated memory, which
    // is backed by the reallocation if's provided above if offsetInLayer ==
    // layer->getHeaderLen() insertData will not move any data but only increase
    // the packet size by numOfBytesToExtend
    insertData(indexToInsertData, nullptr, numOfBytesToExtend);

    // re-calculate all layers data ptr and data length
    const uint8_t* dataPtr = m_RawData;

    // go over all layers from the first layer to the last layer and set the
    // data ptr and data length for each layer
    Layer* curLayer = m_FirstLayer;
    bool passedExtendedLayer = false;
    while (curLayer != nullptr)
    {
        // set the data ptr
        curLayer->m_Data = (uint8_t*)dataPtr;

        // set a flag if arrived to the layer being extended
        if (curLayer->getPrevLayer() == layer)
            passedExtendedLayer = true;

        // change the data length only for layers who come before the extended
        // layer. For layers who come after, data length isn't changed
        if (!passedExtendedLayer)
            curLayer->m_DataLen += numOfBytesToExtend;

        // assuming header length of the layer that requested to be extended
        // hasn't been enlarged yet
        size_t headerLen = curLayer->getHeaderLen() + (curLayer == layer ? numOfBytesToExtend : 0);
        dataPtr += headerLen;
        curLayer = curLayer->getNextLayer();
    }

    return true;
}

bool Packet::shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten)
{
    if (layer == nullptr)
    {
        error("Layer is nullptr");
        return false;
    }

    // verify layer is allocated to this packet
    if (!(layer->m_Packet == this))
    {
        error("Layer isn't allocated to this packet");
        return false;
    }

    // remove data from raw packet
    int indexOfDataToRemove = layer->m_Data + offsetInLayer - m_RawData;
    if (!removeData(indexOfDataToRemove, numOfBytesToShorten))
    {
        error("Couldn't remove data from packet");
        return false;
    }

    // re-calculate all layers data ptr and data length
    const uint8_t* dataPtr = m_RawData;

    // go over all layers from the first layer to the last layer and set the
    // data ptr and data length for each layer
    Layer* curLayer = m_FirstLayer;
    bool passedExtendedLayer = false;
    while (curLayer != nullptr)
    {
        // set the data ptr
        curLayer->m_Data = (uint8_t*)dataPtr;

        // set a flag if arrived to the layer being shortened
        if (curLayer->getPrevLayer() == layer)
            passedExtendedLayer = true;

        // change the data length only for layers who come before the shortened
        // layer. For layers who come after, data length isn't changed
        if (!passedExtendedLayer)
            curLayer->m_DataLen -= numOfBytesToShorten;

        // assuming header length of the layer that requested to be extended
        // hasn't been enlarged yet
        size_t headerLen = curLayer->getHeaderLen() - (curLayer == layer ? numOfBytesToShorten : 0);
        dataPtr += headerLen;
        curLayer = curLayer->getNextLayer();
    }

    return true;
}

void Packet::computeCalculateFields()
{
    // calculated fields should be calculated from top layer to bottom layer

    Layer* curLayer = m_LastLayer;
    while (curLayer != nullptr)
    {
        curLayer->computeCalculateFields();
        curLayer = curLayer->getPrevLayer();
    }
}

std::string Packet::printPacketInfo() const
{
    return casket::format("[{}] Len: {}", timestamp_.toString(), m_RawDataLen);
}

Layer* Packet::createFirstLayer(LinkLayerType linkType)
{
    if (m_RawDataLen == 0)
        return nullptr;

    if (linkType == LINKTYPE_ETHERNET)
    {
        if (EthLayer::isDataValid(m_RawData, m_RawDataLen))
        {
            return new EthLayer(m_RawData, m_RawDataLen, this);
        }
        else
        {
            return new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this);
        }
        return new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this);
    }
    else if (linkType == LINKTYPE_NULL)
    {
        if (m_RawDataLen >= sizeof(uint32_t))
            return new NullLoopbackLayer(m_RawData, m_RawDataLen, this);
        else // rawDataLen is too small fir Null/Loopback
            return new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this);
    }
    else if (linkType == LINKTYPE_RAW || linkType == LINKTYPE_DLT_RAW1 || linkType == LINKTYPE_DLT_RAW2)
    {
        uint8_t ipVer = m_RawData[0] & 0xf0;
        if (ipVer == 0x40)
        {
            return IPv4Layer::isDataValid(m_RawData, m_RawDataLen)
                       ? static_cast<Layer*>(new IPv4Layer(m_RawData, m_RawDataLen, nullptr, this))
                       : static_cast<Layer*>(new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this));
        }
        else if (ipVer == 0x60)
        {
            return IPv6Layer::isDataValid(m_RawData, m_RawDataLen)
                       ? static_cast<Layer*>(new IPv6Layer(m_RawData, m_RawDataLen, nullptr, this))
                       : static_cast<Layer*>(new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this));
        }
        else
        {
            return new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this);
        }
    }
    else if (linkType == LINKTYPE_IPV4)
    {
        return IPv4Layer::isDataValid(m_RawData, m_RawDataLen)
                   ? static_cast<Layer*>(new IPv4Layer(m_RawData, m_RawDataLen, nullptr, this))
                   : static_cast<Layer*>(new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this));
    }
    else if (linkType == LINKTYPE_IPV6)
    {
        return IPv6Layer::isDataValid(m_RawData, m_RawDataLen)
                   ? static_cast<Layer*>(new IPv6Layer(m_RawData, m_RawDataLen, nullptr, this))
                   : static_cast<Layer*>(new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this));
    }

    // unknown link type
    return new PayloadLayer(m_RawData, m_RawDataLen, nullptr, this);
}

std::string Packet::toString() const
{
    std::vector<std::string> stringList;
    toStringList(stringList);
    return std::accumulate(stringList.begin(), stringList.end(), std::string(),
                           [](std::string a, const std::string& b) { return std::move(a) + b + '\n'; });
}

void Packet::toStringList(std::vector<std::string>& result) const
{
    result.clear();
    result.push_back(printPacketInfo());
    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr)
    {
        result.push_back(curLayer->toString());
        curLayer = curLayer->getNextLayer();
    }
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
