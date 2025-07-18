#include <string.h>
#include <sstream>

#include <casket/log/log_manager.hpp>
#include <casket/utils/endianness.hpp>

#include <snet/layers/checksums.hpp>
#include <snet/layers/ipv4_layer.hpp>
#include <snet/layers/ipv6_layer.hpp>
#include <snet/layers/tcp_layer.hpp>
#include <snet/layers/payload_layer.hpp>

using namespace casket;

namespace snet::layers
{

#define IPV4OPT_DUMMY 0xff
#define IPV4_MAX_OPT_SIZE 40

/// ~~~~~~~~~~~~~~~~~
/// IPv4OptionBuilder
/// ~~~~~~~~~~~~~~~~~

IPv4OptionBuilder::IPv4OptionBuilder(IPv4OptionTypes optionType, const std::vector<ip::IPv4Address>& ipList)
{
    m_RecType = (uint8_t)optionType;
    m_RecValueLen = ipList.size() * sizeof(uint32_t) + sizeof(uint8_t);
    m_RecValue = new uint8_t[m_RecValueLen];

    size_t curOffset = 0;
    m_RecValue[curOffset++] = 0; // init pointer value

    bool firstZero = false;
    for (const auto& ipAddr : ipList)
    {
        uint32_t ipAddrAsInt = ipAddr.toUint();

        if (!firstZero)
            m_RecValue[0] += (uint8_t)4;

        if (!firstZero && ipAddrAsInt == 0)
            firstZero = true;

        memcpy(m_RecValue + curOffset, &ipAddrAsInt, sizeof(uint32_t));
        curOffset += sizeof(uint32_t);
    }

    m_BuilderParamsValid = true;
}

IPv4OptionBuilder::IPv4OptionBuilder(const IPv4TimestampOptionValue& timestampValue)
{
    m_RecType = (uint8_t)IPV4OPT_Timestamp;
    m_RecValueLen = 0;
    m_RecValue = nullptr;

    if (timestampValue.type == IPv4TimestampOptionValue::Unknown)
    {
        error("Cannot build timestamp option of type "
              "IPv4TimestampOptionValue::Unknown");
        m_BuilderParamsValid = false;
        return;
    }

    if (timestampValue.type == IPv4TimestampOptionValue::TimestampsForPrespecifiedIPs)
    {
        error("Cannot build timestamp option of type "
              "IPv4TimestampOptionValue::TimestampsForPrespecifiedIPs "
              "- this type is not supported");
        m_BuilderParamsValid = false;
        return;
    }

    if (timestampValue.type == IPv4TimestampOptionValue::TimestampAndIP &&
        timestampValue.timestamps.size() != timestampValue.ipAddresses.size())
    {
        error("Cannot build timestamp option of type "
              "IPv4TimestampOptionValue::TimestampAndIP because "
              "number of timestamps and IP addresses is not equal");
        m_BuilderParamsValid = false;
        return;
    }

    m_RecValueLen = timestampValue.timestamps.size() * sizeof(uint32_t) + 2 * sizeof(uint8_t);

    if (timestampValue.type == IPv4TimestampOptionValue::TimestampAndIP)
    {
        m_RecValueLen += timestampValue.timestamps.size() * sizeof(uint32_t);
    }

    m_RecValue = new uint8_t[m_RecValueLen];

    size_t curOffset = 0;
    m_RecValue[curOffset++] = 1; // pointer default value is 1 - means there are no empty timestamps
    m_RecValue[curOffset++] = (uint8_t)timestampValue.type; // timestamp type

    int firstZero = -1;
    for (int i = 0; i < (int)timestampValue.timestamps.size(); i++)
    {
        uint32_t timestamp = host_to_be(timestampValue.timestamps.at(i));

        // for pointer calculation - find the first timestamp equals to 0
        if (timestamp == 0 && firstZero == -1)
            firstZero = i;

        if (timestampValue.type == IPv4TimestampOptionValue::TimestampAndIP)
        {
            uint32_t ipAddrAsInt = timestampValue.ipAddresses.at(i).toUint();
            memcpy(m_RecValue + curOffset, &ipAddrAsInt, sizeof(uint32_t));
            curOffset += sizeof(uint32_t);
        }

        memcpy(m_RecValue + curOffset, &timestamp, sizeof(uint32_t));
        curOffset += sizeof(uint32_t);
    }

    // calculate pointer field
    if (firstZero > -1)
    {
        uint8_t pointerVal = (uint8_t)(4 * sizeof(uint8_t) + firstZero * sizeof(uint32_t) + 1);
        if (timestampValue.type == IPv4TimestampOptionValue::TimestampAndIP)
            pointerVal += (uint8_t)(firstZero * sizeof(uint32_t));

        m_RecValue[0] = pointerVal;
    }

    m_BuilderParamsValid = true;
}

IPv4Option IPv4OptionBuilder::build() const
{
    if (!m_BuilderParamsValid)
        return IPv4Option(nullptr);

    size_t optionSize = m_RecValueLen + 2 * sizeof(uint8_t);

    uint8_t recType = static_cast<uint8_t>(m_RecType);
    if ((recType == (uint8_t)IPV4OPT_NOP || recType == (uint8_t)IPV4OPT_EndOfOptionsList))
    {
        if (m_RecValueLen != 0)
        {
            error("Can't set IPv4 NOP option or IPv4 End-of-options option with "
                  "size different than 0, tried to set size {}",
                  m_RecValueLen);
            return IPv4Option(nullptr);
        }

        optionSize = sizeof(uint8_t);
    }

    uint8_t* recordBuffer = new uint8_t[optionSize];
    memset(recordBuffer, 0, optionSize);
    recordBuffer[0] = recType;
    if (optionSize > 1)
    {
        recordBuffer[1] = static_cast<uint8_t>(optionSize);
        if (optionSize > 2 && m_RecValue != nullptr)
            memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);
    }

    return IPv4Option(recordBuffer);
}

/// ~~~~~~~~~
/// IPv4Layer
/// ~~~~~~~~~

void IPv4Layer::initLayer()
{
    const size_t headerLen = sizeof(iphdr);
    m_DataLen = headerLen;
    m_Data = new uint8_t[headerLen];
    m_Protocol = IPv4;
    memset(m_Data, 0, headerLen);
    iphdr* ipHdr = getIPv4Header();
    ipHdr->internetHeaderLength = (5 & 0xf);
    m_NumOfTrailingBytes = 0;
    m_TempHeaderExtension = 0;
}

void IPv4Layer::initLayerInPacket(bool setTotalLenAsDataLen)
{
    m_Protocol = IPv4;
    m_NumOfTrailingBytes = 0;
    m_TempHeaderExtension = 0;
    if (setTotalLenAsDataLen)
    {
        size_t totalLen = be_to_host(getIPv4Header()->totalLength);
        // if totalLen == 0 this usually means TCP Segmentation Offload (TSO).
        // In this case we should ignore the value of totalLen and look at the
        // data captured on the wire
        if ((totalLen < m_DataLen) && (totalLen != 0))
            m_DataLen = totalLen;
    }
}

void IPv4Layer::copyLayerData(const IPv4Layer& other)
{
    m_OptionReader = other.m_OptionReader;
    m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
    m_TempHeaderExtension = other.m_TempHeaderExtension;
}

IPv4Layer::IPv4Layer()
{
    initLayer();
}

IPv4Layer::IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen)
    : Layer(data, dataLen, prevLayer, packet)
{
    initLayerInPacket(setTotalLenAsDataLen);
}

IPv4Layer::IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
    : Layer(data, dataLen, prevLayer, packet)
{
    initLayerInPacket(true);
}

IPv4Layer::IPv4Layer(const ip::IPv4Address& srcIP, const ip::IPv4Address& dstIP)
{
    initLayer();
    iphdr* ipHdr = getIPv4Header();
    ipHdr->ipSrc = srcIP.toUint();
    ipHdr->ipDst = dstIP.toUint();
}

IPv4Layer::IPv4Layer(const IPv4Layer& other)
    : Layer(other)
{
    copyLayerData(other);
}

IPv4Layer& IPv4Layer::operator=(const IPv4Layer& other)
{
    Layer::operator=(other);

    copyLayerData(other);

    return *this;
}

void IPv4Layer::parseNextLayer()
{
    size_t hdrLen = getHeaderLen();
    if (m_DataLen <= hdrLen || hdrLen == 0)
        return;

    iphdr* ipHdr = getIPv4Header();

    uint8_t* payload = m_Data + hdrLen;
    size_t payloadLen = m_DataLen - hdrLen;

    // If it's a fragment don't parse upper layers, unless if it's the first
    // fragment
    // TODO: assuming first fragment contains at least L4 header, what if it's
    // not true?
    if (isFragment())
    {
        m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
        return;
    }

    switch (ipHdr->protocol)
    {
    case PACKETPP_IPPROTO_TCP:
        m_NextLayer = TcpLayer::isDataValid(payload, payloadLen)
                          ? static_cast<Layer*>(new TcpLayer(payload, payloadLen, this, m_Packet))
                          : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
    case PACKETPP_IPPROTO_IPV6:
        m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
                          ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
                          : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
    default:
        m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
    }
}

void IPv4Layer::computeCalculateFields()
{
    iphdr* ipHdr = getIPv4Header();
    ipHdr->ipVersion = (4 & 0x0f);
    ipHdr->totalLength = host_to_be<uint16_t>(m_DataLen);
    ipHdr->headerChecksum = 0;

    if (m_NextLayer != nullptr)
    {
        switch (m_NextLayer->getProtocol())
        {
        case TCP:
            ipHdr->protocol = PACKETPP_IPPROTO_TCP;
            break;
        case UDP:
            ipHdr->protocol = PACKETPP_IPPROTO_UDP;
            break;
        case ICMP:
            ipHdr->protocol = PACKETPP_IPPROTO_ICMP;
            break;
        case GREv0:
        case GREv1:
            ipHdr->protocol = PACKETPP_IPPROTO_GRE;
            break;
        case IGMPv1:
        case IGMPv2:
        case IGMPv3:
            ipHdr->protocol = PACKETPP_IPPROTO_IGMP;
            break;
        case VRRPv2:
        case VRRPv3:
            ipHdr->protocol = PACKETPP_IPPROTO_VRRP;
            break;
        default:
            break;
        }
    }

    ScalarBuffer<uint16_t> scalar = {(uint16_t*)ipHdr, (size_t)(ipHdr->internetHeaderLength * 4)};
    ipHdr->headerChecksum = host_to_be(computeChecksum(&scalar, 1));
}

bool IPv4Layer::isFragment() const
{
    return ((getFragmentFlags() & SNET_IP_MORE_FRAGMENTS) != 0 || getFragmentOffset() != 0);
}

bool IPv4Layer::isFirstFragment() const
{
    return isFragment() && (getFragmentOffset() == 0);
}

bool IPv4Layer::isLastFragment() const
{
    return isFragment() && ((getFragmentFlags() & SNET_IP_MORE_FRAGMENTS) == 0);
}

uint8_t IPv4Layer::getFragmentFlags() const
{
    return getIPv4Header()->fragmentOffset & 0xE0;
}

uint16_t IPv4Layer::getFragmentOffset() const
{
    return be_to_host(getIPv4Header()->fragmentOffset & (uint16_t)0xFF1F) * 8;
}

std::string IPv4Layer::toString() const
{
    std::string fragment = "";
    if (isFragment())
    {
        if (isFirstFragment())
            fragment = "First fragment";
        else if (isLastFragment())
            fragment = "Last fragment";
        else
            fragment = "Fragment";

        std::stringstream sstm;
        sstm << fragment << " [offset= " << getFragmentOffset() << "], ";
        fragment = sstm.str();
    }

    return "IPv4 Layer, " + fragment + "Src: " + getSrcIPv4Address().toString() +
           ", Dst: " + getDstIPv4Address().toString();
}

IPv4Option IPv4Layer::getOption(IPv4OptionTypes option) const
{
    return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(iphdr));
}

IPv4Option IPv4Layer::getFirstOption() const
{
    return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(iphdr));
}

IPv4Option IPv4Layer::getNextOption(IPv4Option& option) const
{
    return m_OptionReader.getNextTLVRecord(option, getOptionsBasePtr(), getHeaderLen() - sizeof(iphdr));
}

size_t IPv4Layer::getOptionCount() const
{
    return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(iphdr));
}

void IPv4Layer::adjustOptionsTrailer(size_t totalOptSize)
{
    size_t ipHdrSize = sizeof(iphdr);

    int newNumberOfTrailingBytes = 0;
    while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
        newNumberOfTrailingBytes++;

    if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
        shortenLayer(ipHdrSize + totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes);
    else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
        extendLayer(ipHdrSize + totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

    m_NumOfTrailingBytes = newNumberOfTrailingBytes;

    for (int i = 0; i < m_NumOfTrailingBytes; i++)
        m_Data[ipHdrSize + totalOptSize + i] = IPV4OPT_DUMMY;

    m_TempHeaderExtension = 0;
    getIPv4Header()->internetHeaderLength = ((ipHdrSize + totalOptSize + m_NumOfTrailingBytes) / 4 & 0x0f);
}

IPv4Option IPv4Layer::addOptionAt(const IPv4OptionBuilder& optionBuilder, int offset)
{
    IPv4Option newOption = optionBuilder.build();
    if (newOption.isNull())
        return newOption;

    size_t sizeToExtend = newOption.getTotalSize();

    size_t totalOptSize = getHeaderLen() - sizeof(iphdr) - m_NumOfTrailingBytes + sizeToExtend;

    if (totalOptSize > IPV4_MAX_OPT_SIZE)
    {
        error("Cannot add option - adding this option will exceed "
              "IPv4 total option size which is {}",
              IPV4_MAX_OPT_SIZE);
        newOption.purgeRecordData();
        return IPv4Option(nullptr);
    }

    if (!extendLayer(offset, sizeToExtend))
    {
        error("Could not extend IPv4Layer in [{}] bytes", sizeToExtend);
        newOption.purgeRecordData();
        return IPv4Option(nullptr);
    }

    memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

    newOption.purgeRecordData();

    // setting this m_TempHeaderExtension because adjustOptionsTrailer() may
    // extend or shorten the layer and the extend or shorten methods need to
    // know the accurate current size of the header. m_TempHeaderExtension will
    // be added to the length extracted from
    // getIPv4Header()->internetHeaderLength as the temp new size
    m_TempHeaderExtension = sizeToExtend;
    adjustOptionsTrailer(totalOptSize);
    // the adjustOptionsTrailer() adds or removed the trailing bytes and sets
    // getIPv4Header()->internetHeaderLength to the correct size, so the
    // m_TempHeaderExtension isn't needed anymore
    m_TempHeaderExtension = 0;

    m_OptionReader.changeTLVRecordCount(1);

    uint8_t* newOptPtr = m_Data + offset;

    return IPv4Option(newOptPtr);
}

IPv4Option IPv4Layer::addOption(const IPv4OptionBuilder& optionBuilder)
{
    return addOptionAt(optionBuilder, getHeaderLen() - m_NumOfTrailingBytes);
}

IPv4Option IPv4Layer::addOptionAfter(const IPv4OptionBuilder& optionBuilder, IPv4OptionTypes prevOptionType)
{
    int offset = 0;

    IPv4Option prevOpt = getOption(prevOptionType);

    if (prevOpt.isNull())
    {
        offset = sizeof(iphdr);
    }
    else
    {
        offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
    }

    return addOptionAt(optionBuilder, offset);
}

bool IPv4Layer::removeOption(IPv4OptionTypes option)
{
    IPv4Option opt = getOption(option);
    if (opt.isNull())
    {
        return false;
    }

    // calculate total option size
    IPv4Option curOpt = getFirstOption();
    size_t totalOptSize = 0;
    while (!curOpt.isNull())
    {
        totalOptSize += curOpt.getTotalSize();
        curOpt = getNextOption(curOpt);
    }
    totalOptSize -= opt.getTotalSize();

    int offset = opt.getRecordBasePtr() - m_Data;

    size_t sizeToShorten = opt.getTotalSize();
    if (!shortenLayer(offset, sizeToShorten))
    {
        error("Failed to remove IPv4 option: cannot shorten layer");
        return false;
    }

    // setting this m_TempHeaderExtension because adjustOptionsTrailer() may
    // extend or shorten the layer and the extend or shorten methods need to
    // know the accurate current size of the header. m_TempHeaderExtension will
    // be added to the length extracted from
    // getIPv4Header()->internetHeaderLength as the temp new size
    m_TempHeaderExtension = 0 - sizeToShorten;
    adjustOptionsTrailer(totalOptSize);
    // the adjustOptionsTrailer() adds or removed the trailing bytes and sets
    // getIPv4Header()->internetHeaderLength to the correct size, so the
    // m_TempHeaderExtension isn't needed anymore
    m_TempHeaderExtension = 0;

    m_OptionReader.changeTLVRecordCount(-1);

    return true;
}

bool IPv4Layer::removeAllOptions()
{
    int offset = sizeof(iphdr);

    if (!shortenLayer(offset, getHeaderLen() - offset))
        return false;

    getIPv4Header()->internetHeaderLength = (5 & 0xf);
    m_NumOfTrailingBytes = 0;
    m_OptionReader.changeTLVRecordCount(0 - getOptionCount());
    return true;
}

} // namespace snet::layers
