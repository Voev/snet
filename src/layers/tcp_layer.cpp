#include <string.h>
#include <sstream>

#include <snet/log/log_manager.hpp>
#include <snet/layers/checksums.hpp>
#include <snet/layers/tcp_layer.hpp>
#include <snet/layers/ipv4_layer.hpp>
#include <snet/layers/ipv6_layer.hpp>
#include <snet/layers/payload_layer.hpp>

#include <snet/utils/endianness.hpp>

using namespace snet::utils;

namespace snet::layers
{

#define TCPOPT_DUMMY 0xff

/// ~~~~~~~~~~~~~~~~
/// TcpOptionBuilder
/// ~~~~~~~~~~~~~~~~

TcpOptionBuilder::TcpOptionBuilder(const NopEolOptionEnumType optionType)
{
    switch (optionType)
    {
    case NopEolOptionEnumType::Eol:
        init(static_cast<uint8_t>(TcpOptionEnumType::Eol), nullptr, 0);
        break;
    case NopEolOptionEnumType::Nop:
    default:
        init(static_cast<uint8_t>(TcpOptionEnumType::Nop), nullptr, 0);
        break;
    }
}

TcpOption TcpOptionBuilder::build() const
{
    uint8_t recType = static_cast<uint8_t>(m_RecType);
    size_t optionSize = m_RecValueLen + 2 * sizeof(uint8_t);

    if (recType == static_cast<uint8_t>(TcpOptionEnumType::Eol) ||
        recType == static_cast<uint8_t>(TcpOptionEnumType::Nop))
    {
        if (m_RecValueLen != 0)
        {
            log::error("TCP NOP and TCP EOL options are 1-byte long and don't have "
                       "option value. Tried to set option value of size {}",
                       m_RecValueLen);
            return TcpOption(nullptr);
        }

        optionSize = 1;
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

    return TcpOption(recordBuffer);
}

/// ~~~~~~~~
/// TcpLayer
/// ~~~~~~~~

uint16_t TcpLayer::getSrcPort() const
{
    return be_to_host(getTcpHeader()->portSrc);
}

uint16_t TcpLayer::getDstPort() const
{
    return be_to_host(getTcpHeader()->portDst);
}

TcpOption TcpLayer::getTcpOption(const TcpOptionEnumType option) const
{
    return m_OptionReader.getTLVRecord(static_cast<uint8_t>(option), getOptionsBasePtr(),
                                       getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::getFirstTcpOption() const
{
    return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::getNextTcpOption(TcpOption& tcpOption) const
{
    TcpOption nextOpt = m_OptionReader.getNextTLVRecord(tcpOption, getOptionsBasePtr(),
                                                        getHeaderLen() - sizeof(tcphdr));
    if (nextOpt.isNotNull() && nextOpt.getType() == TCPOPT_DUMMY)
        return TcpOption(nullptr);

    return nextOpt;
}

size_t TcpLayer::getTcpOptionCount() const
{
    return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

TcpOption TcpLayer::addTcpOption(const TcpOptionBuilder& optionBuilder)
{
    return addTcpOptionAt(optionBuilder, getHeaderLen() - m_NumOfTrailingBytes);
}

TcpOption TcpLayer::insertTcpOptionAfter(const TcpOptionBuilder& optionBuilder,
                                         const TcpOptionEnumType prevOptionType)
{
    int offset = 0;

    if (prevOptionType == TcpOptionEnumType::Unknown)
    {
        offset = sizeof(tcphdr);
    }
    else
    {
        const TcpOption prevOpt = getTcpOption(prevOptionType);
        if (prevOpt.isNull())
        {
            log::error("Previous option of type {} not found, cannot add a new TCP option",
                       (int)prevOptionType);
            return TcpOption(nullptr);
        }

        offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
    }

    return addTcpOptionAt(optionBuilder, offset);
}

bool TcpLayer::removeTcpOption(const TcpOptionEnumType optionType)
{
    const TcpOption opt = getTcpOption(optionType);
    if (opt.isNull())
    {
        return false;
    }

    // calculate total TCP option size
    TcpOption curOpt = getFirstTcpOption();
    size_t totalOptSize = 0;
    while (!curOpt.isNull())
    {
        totalOptSize += curOpt.getTotalSize();
        curOpt = getNextTcpOption(curOpt);
    }
    totalOptSize -= opt.getTotalSize();

    int offset = opt.getRecordBasePtr() - m_Data;

    if (!shortenLayer(offset, opt.getTotalSize()))
    {
        return false;
    }

    adjustTcpOptionTrailer(totalOptSize);

    m_OptionReader.changeTLVRecordCount(-1);

    return true;
}

bool TcpLayer::removeAllTcpOptions()
{
    const int offset = sizeof(tcphdr);

    if (!shortenLayer(offset, getHeaderLen() - offset))
        return false;

    getTcpHeader()->dataOffset = sizeof(tcphdr) / 4;
    m_NumOfTrailingBytes = 0;
    m_OptionReader.changeTLVRecordCount(0 - getTcpOptionCount());
    return true;
}

TcpOption TcpLayer::addTcpOptionAt(const TcpOptionBuilder& optionBuilder, const int offset)
{
    TcpOption newOption = optionBuilder.build();
    if (newOption.isNull())
        return newOption;

    // calculate total TCP option size
    TcpOption curOpt = getFirstTcpOption();
    size_t totalOptSize = 0;
    while (!curOpt.isNull())
    {
        totalOptSize += curOpt.getTotalSize();
        curOpt = getNextTcpOption(curOpt);
    }
    totalOptSize += newOption.getTotalSize();

    size_t sizeToExtend = newOption.getTotalSize();

    if (!extendLayer(offset, sizeToExtend))
    {
        log::error("Could not extend TcpLayer in [{}] bytes", sizeToExtend);
        newOption.purgeRecordData();
        return TcpOption(nullptr);
    }

    memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

    newOption.purgeRecordData();

    adjustTcpOptionTrailer(totalOptSize);

    m_OptionReader.changeTLVRecordCount(1);

    uint8_t* newOptPtr = m_Data + offset;

    return TcpOption(newOptPtr);
}

void TcpLayer::adjustTcpOptionTrailer(const size_t totalOptSize)
{
    int newNumberOfTrailingBytes = 0;
    while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
        newNumberOfTrailingBytes++;

    if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
        shortenLayer(sizeof(tcphdr) + totalOptSize,
                     m_NumOfTrailingBytes - newNumberOfTrailingBytes - 1);
    else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
        extendLayer(sizeof(tcphdr) + totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

    m_NumOfTrailingBytes = newNumberOfTrailingBytes;

    for (int i = 0; i < m_NumOfTrailingBytes; i++)
        m_Data[sizeof(tcphdr) + totalOptSize + i] = TCPOPT_DUMMY;

    getTcpHeader()->dataOffset = (sizeof(tcphdr) + totalOptSize + m_NumOfTrailingBytes) / 4;
}

uint16_t TcpLayer::calculateChecksum(const bool writeResultToPacket)
{
    tcphdr* tcpHdr = getTcpHeader();
    uint16_t checksumRes = 0;
    const uint16_t currChecksumValue = tcpHdr->headerChecksum;

    if (m_PrevLayer != nullptr)
    {
        tcpHdr->headerChecksum = 0;
        log::debug("TCP data len = {}");

        if (m_PrevLayer->getProtocol() == IPv4)
        {
            const ip::IPv4Address srcIP = static_cast<IPv4Layer*>(m_PrevLayer)->getSrcIPv4Address();
            const ip::IPv4Address dstIP = static_cast<IPv4Layer*>(m_PrevLayer)->getDstIPv4Address();

            checksumRes = snet::layers::computePseudoHdrChecksum(
                reinterpret_cast<uint8_t*>(tcpHdr), getDataLen(), ip::IPAddress::IPv4,
                PACKETPP_IPPROTO_TCP, srcIP, dstIP);
        }
        else if (m_PrevLayer->getProtocol() == IPv6)
        {
            const ip::IPv6Address srcIP = static_cast<IPv6Layer*>(m_PrevLayer)->getSrcIPv6Address();
            const ip::IPv6Address dstIP = static_cast<IPv6Layer*>(m_PrevLayer)->getDstIPv6Address();

            checksumRes =
                computePseudoHdrChecksum(reinterpret_cast<uint8_t*>(tcpHdr), getDataLen(),
                                         ip::IPAddress::IPv6, PACKETPP_IPPROTO_TCP, srcIP, dstIP);
        }
    }

    if (writeResultToPacket)
        tcpHdr->headerChecksum = host_to_be(checksumRes);
    else
        tcpHdr->headerChecksum = currChecksumValue;

    return checksumRes;
}

void TcpLayer::initLayer()
{
    m_DataLen = sizeof(tcphdr);
    m_Data = new uint8_t[m_DataLen];
    memset(m_Data, 0, m_DataLen);
    m_Protocol = TCP;
    m_NumOfTrailingBytes = 0;
    getTcpHeader()->dataOffset = sizeof(tcphdr) / 4;
}

TcpLayer::TcpLayer(uint8_t* data, const size_t dataLen, Layer* prevLayer, Packet* packet)
    : Layer(data, dataLen, prevLayer, packet, TCP)
{
    m_NumOfTrailingBytes = 0;
}

TcpLayer::TcpLayer()
{
    initLayer();
}

TcpLayer::TcpLayer(const uint16_t portSrc, const uint16_t portDst)
{
    initLayer();
    getTcpHeader()->portDst = host_to_be(portDst);
    getTcpHeader()->portSrc = host_to_be(portSrc);
}

void TcpLayer::copyLayerData(const TcpLayer& other)
{
    m_OptionReader = other.m_OptionReader;
    m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
}

TcpLayer::TcpLayer(const TcpLayer& other)
    : Layer(other)
{
    copyLayerData(other);
}

TcpLayer& TcpLayer::operator=(const TcpLayer& other)
{
    Layer::operator=(other);

    copyLayerData(other);

    return *this;
}

void TcpLayer::parseNextLayer()
{
    const size_t headerLen = getHeaderLen();
    if (m_DataLen <= headerLen)
        return;

    uint8_t* payload = m_Data + headerLen;
    const size_t payloadLen = m_DataLen - headerLen;

    m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
}

void TcpLayer::computeCalculateFields()
{
    tcphdr* tcpHdr = getTcpHeader();

    tcpHdr->dataOffset = getHeaderLen() >> 2;
    calculateChecksum(true);
}

std::string TcpLayer::toString() const
{
    const tcphdr* hdr = getTcpHeader();
    std::string result = "TCP Layer, ";
    if (hdr->synFlag)
    {
        if (hdr->ackFlag)
            result += "[SYN, ACK], ";
        else
            result += "[SYN], ";
    }
    else if (hdr->finFlag)
    {
        if (hdr->ackFlag)
            result += "[FIN, ACK], ";
        else
            result += "[FIN], ";
    }
    else if (hdr->ackFlag)
        result += "[ACK], ";

    std::ostringstream srcPortStream;
    srcPortStream << getSrcPort();
    std::ostringstream dstPortStream;
    dstPortStream << getDstPort();
    result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();

    return result;
}

} // namespace snet::layers
