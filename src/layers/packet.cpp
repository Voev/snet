#include <string.h>
#include <numeric>
#include <typeinfo>
#include <sstream>
#include <ctime>

#include <casket/log/log_manager.hpp>

#include <snet/layers/packet.hpp>
#include <snet/layers/eth_layer.hpp>
#include <snet/layers/loopback.hpp>
#include <snet/layers/ipv4_layer.hpp>
#include <snet/layers/ipv6_layer.hpp>
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

Packet::Packet(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor,
               LinkLayerType layerType)
    : m_DeleteRawDataAtDestructor(deleteRawDataAtDestructor)
{
    timespec nsec_time = {};
    TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
    setRawData(pRawData, rawDataLen, nsec_time, layerType, -1);
}

Packet::Packet(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
               LinkLayerType layerType)
    : m_DeleteRawDataAtDestructor(deleteRawDataAtDestructor)
{
    setRawData(pRawData, rawDataLen, timestamp, layerType, -1);
}

Packet::Packet(size_t maxPacketLen)
    : m_MaxPacketLen(maxPacketLen)
    , m_CanReallocateData(true)
    , m_DeleteRawDataAtDestructor(true)
{
    timeval time;
    gettimeofday(&time, nullptr);
    uint8_t* data = new uint8_t[maxPacketLen];
    memset(data, 0, maxPacketLen);

    setRawData(data, 0, time, LINKTYPE_ETHERNET, -1);
}

Packet::Packet(uint8_t* buffer, size_t bufferSize)
    : m_MaxPacketLen(bufferSize)
{
    timeval time;
    gettimeofday(&time, nullptr);
    memset(buffer, 0, bufferSize);

    setRawData(buffer, 0, time, LINKTYPE_ETHERNET, -1);
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

Packet::Packet(const Packet& other)
{
    m_RawData = nullptr;
    copyDataFrom(other, true);
}

Packet& Packet::operator=(const Packet& other)
{
    if (this != &other)
    {
        if (m_RawData != nullptr)
            delete[] m_RawData;

        m_RawPacketSet = false;

        copyDataFrom(other, true);
    }

    return *this;
}

Packet* Packet::clone() const
{
    return new Packet(*this);
}

void Packet::copyDataFrom(const Packet& other, bool allocateData)
{
    if (!other.m_RawPacketSet)
        return;

    m_TimeStamp = other.m_TimeStamp;

    if (allocateData)
    {
        m_DeleteRawDataAtDestructor = true;
        m_RawData = new uint8_t[other.m_RawDataLen];
        m_RawDataLen = other.m_RawDataLen;
    }

    memcpy(m_RawData, other.m_RawData, other.m_RawDataLen);
    m_LinkLayerType = other.m_LinkLayerType;
    m_FrameLength = other.m_FrameLength;
    m_RawPacketSet = true;
}

bool Packet::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType,
                        int frameLength)
{
    timespec nsec_time;
    TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
    return setRawData(pRawData, rawDataLen, nsec_time, layerType, frameLength);
}

bool Packet::setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType,
                        int frameLength)
{
    if (frameLength == -1)
    {
        frameLength = rawDataLen;
    }

    m_FrameLength = frameLength;
    if (m_RawData && m_DeleteRawDataAtDestructor)
    {
        delete[] m_RawData;
    }

    m_RawData = (uint8_t*)pRawData;
    m_RawDataLen = rawDataLen;
    m_TimeStamp = timestamp;
    m_RawPacketSet = true;
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
    m_RawPacketSet = false;
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

bool Packet::setPacketTimeStamp(timeval timestamp)
{
    timespec nsec_time;
    TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
    return setPacketTimeStamp(nsec_time);
}

bool Packet::setPacketTimeStamp(timespec timestamp)
{
    m_TimeStamp = timestamp;
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


void Packet::copyDataFrom(const Packet& other)
{
    m_MaxPacketLen = other.m_MaxPacketLen;
    m_FirstLayer = createFirstLayer(getLinkLayerType());
    m_LastLayer = m_FirstLayer;
    m_CanReallocateData = true;
    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr)
    {
        curLayer->parseNextLayer();
        curLayer->m_IsAllocatedInPacket = true;
        curLayer = curLayer->getNextLayer();
        if (curLayer != nullptr)
            m_LastLayer = curLayer;
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

bool Packet::insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket)
{
    if (newLayer == nullptr)
    {
        error("Layer to add is nullptr");
        return false;
    }

    if (newLayer->isAllocatedToPacket())
    {
        error("Layer is already allocated to another packet. Cannot "
              "use layer in more than one packet");
        return false;
    }

    if (prevLayer != nullptr && prevLayer->getProtocol() == PacketTrailer)
    {
        error("Cannot insert layer after packet trailer");
        return false;
    }

    size_t newLayerHeaderLen = newLayer->getHeaderLen();
    if (m_RawDataLen + newLayerHeaderLen > m_MaxPacketLen)
    {
        if (!m_CanReallocateData)
        {
            error("With the new layer the packet will exceed the size "
                  "of the pre-allocated buffer: {} bytes ",
                  m_MaxPacketLen);
            return false;
        }
        // reallocate to maximum value of: twice the max size of the packet or
        // max size + new required length
        if (m_RawDataLen + newLayerHeaderLen > m_MaxPacketLen * 2)
            reallocateRawData(m_RawDataLen + newLayerHeaderLen + m_MaxPacketLen);
        else
            reallocateRawData(m_MaxPacketLen * 2);
    }

    // insert layer data to raw packet
    int indexToInsertData = 0;
    if (prevLayer != nullptr)
        indexToInsertData = prevLayer->m_Data + prevLayer->getHeaderLen() - m_RawData;
    insertData(indexToInsertData, newLayer->m_Data, newLayerHeaderLen);

    // delete previous layer data
    delete[] newLayer->m_Data;

    // add layer to layers linked list
    if (prevLayer != nullptr)
    {
        newLayer->setNextLayer(prevLayer->getNextLayer());
        newLayer->setPrevLayer(prevLayer);
        prevLayer->setNextLayer(newLayer);
    }
    else // prevLayer == nullptr
    {
        newLayer->setNextLayer(m_FirstLayer);
        if (m_FirstLayer != nullptr)
            m_FirstLayer->setPrevLayer(newLayer);
        m_FirstLayer = newLayer;
    }

    if (newLayer->getNextLayer() == nullptr)
        m_LastLayer = newLayer;
    else
        newLayer->getNextLayer()->setPrevLayer(newLayer);

    // assign layer with this packet only
    newLayer->m_Packet = this;

    // Set flag to indicate if new layer is allocated to packet.
    if (ownInPacket)
        newLayer->m_IsAllocatedInPacket = true;

    // re-calculate all layers data ptr and data length

    // first, get ptr and data length of the raw packet
    const uint8_t* dataPtr = m_RawData;
    size_t dataLen = (size_t)m_RawDataLen;

    // if a packet trailer exists, get its length
    size_t packetTrailerLen = 0;
    if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
        packetTrailerLen = m_LastLayer->getDataLen();

    // go over all layers from the first layer to the last layer and set the
    // data ptr and data length for each one
    Layer* curLayer = m_FirstLayer;
    while (curLayer != nullptr)
    {
        // set data ptr to layer
        curLayer->m_Data = (uint8_t*)dataPtr;

        // there is an assumption here that the packet trailer, if exists,
        // corresponds to the L2 (data link) layers. so if there is a packet
        // trailer and this layer is L2 (data link), set its data length to
        // contain the whole data, including the packet trailer. If this layer
        // is L3-7, exclude the packet trailer from its data length
        if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
            curLayer->m_DataLen = dataLen;
        else
            curLayer->m_DataLen = dataLen - packetTrailerLen;

        // advance data ptr and data length
        dataPtr += curLayer->getHeaderLen();
        dataLen -= curLayer->getHeaderLen();

        // move to next layer
        curLayer = curLayer->getNextLayer();
    }

    return true;
}

bool Packet::removeLayer(ProtocolType layerType, int index)
{
    Layer* layerToRemove = getLayerOfType(layerType, index);

    if (layerToRemove != nullptr)
    {
        return removeLayer(layerToRemove, true);
    }
    else
    {
        error("Layer of the requested type was not found in packet");
        return false;
    }
}

bool Packet::removeFirstLayer()
{
    Layer* firstLayer = getFirstLayer();
    if (firstLayer == nullptr)
    {
        error("Packet has no layers");
        return false;
    }

    return removeLayer(firstLayer, true);
}

bool Packet::removeLastLayer()
{
    Layer* lastLayer = getLastLayer();
    if (lastLayer == nullptr)
    {
        error("Packet has no layers");
        return false;
    }

    return removeLayer(lastLayer, true);
}

bool Packet::removeAllLayersAfter(Layer* layer)
{
    Layer* curLayer = layer->getNextLayer();
    while (curLayer != nullptr)
    {
        Layer* tempLayer = curLayer->getNextLayer();
        if (!removeLayer(curLayer, true))
            return false;
        curLayer = tempLayer;
    }

    return true;
}

Layer* Packet::detachLayer(ProtocolType layerType, int index)
{
    Layer* layerToDetach = getLayerOfType(layerType, index);

    if (layerToDetach != nullptr)
    {
        if (removeLayer(layerToDetach, false))
            return layerToDetach;
        else
            return nullptr;
    }
    else
    {
        error("Layer of the requested type was not found in packet");
        return nullptr;
    }
}

bool Packet::removeLayer(Layer* layer, bool tryToDelete)
{
    if (layer == nullptr)
    {
        error("Layer is nullptr");
        return false;
    }

    // verify layer is allocated to a packet
    if (!layer->isAllocatedToPacket())
    {
        error("Layer isn't allocated to any packet");
        return false;
    }

    // verify layer is allocated to *this* packet
    Layer* curLayer = layer;
    while (curLayer->m_PrevLayer != nullptr)
        curLayer = curLayer->m_PrevLayer;
    if (curLayer != m_FirstLayer)
    {
        error("Layer isn't allocated to this packet");
        return false;
    }

    // before removing the layer's data, copy it so it can be later assigned as
    // the removed layer's data
    size_t headerLen = layer->getHeaderLen();
    size_t layerOldDataSize = headerLen;
    uint8_t* layerOldData = new uint8_t[layerOldDataSize];
    memcpy(layerOldData, layer->m_Data, layerOldDataSize);

    // remove data from raw packet
    size_t numOfBytesToRemove = headerLen;
    int indexOfDataToRemove = layer->m_Data - m_RawData;
    if (!removeData(indexOfDataToRemove, numOfBytesToRemove))
    {
        error("Couldn't remove data from packet");
        delete[] layerOldData;
        return false;
    }

    // remove layer from layers linked list
    if (layer->m_PrevLayer != nullptr)
        layer->m_PrevLayer->setNextLayer(layer->m_NextLayer);
    if (layer->m_NextLayer != nullptr)
        layer->m_NextLayer->setPrevLayer(layer->m_PrevLayer);

    // take care of head and tail ptrs
    if (m_FirstLayer == layer)
        m_FirstLayer = layer->m_NextLayer;
    if (m_LastLayer == layer)
        m_LastLayer = layer->m_PrevLayer;
    layer->setNextLayer(nullptr);
    layer->setPrevLayer(nullptr);

    // get packet trailer len if exists
    size_t packetTrailerLen = 0;
    if (m_LastLayer != nullptr && m_LastLayer->getProtocol() == PacketTrailer)
        packetTrailerLen = m_LastLayer->getDataLen();

    // re-calculate all layers data ptr and data length

    // first, get ptr and data length of the raw packet
    const uint8_t* dataPtr = m_RawData;
    size_t dataLen = (size_t)m_RawDataLen;

    curLayer = m_FirstLayer;

    // go over all layers from the first layer to the last layer and set the
    // data ptr and data length for each one
    while (curLayer != nullptr)
    {
        // set data ptr to layer
        curLayer->m_Data = (uint8_t*)dataPtr;

        // there is an assumption here that the packet trailer, if exists,
        // corresponds to the L2 (data link) layers. so if there is a packet
        // trailer and this layer is L2 (data link), set its data length to
        // contain the whole data, including the packet trailer. If this layer
        // is L3-7, exclude the packet trailer from its data length
        if (curLayer->getOsiModelLayer() == OsiModelDataLinkLayer)
            curLayer->m_DataLen = dataLen;
        else
            curLayer->m_DataLen = dataLen - packetTrailerLen;

        // advance data ptr and data length
        dataPtr += curLayer->getHeaderLen();
        dataLen -= curLayer->getHeaderLen();

        // move to next layer
        curLayer = curLayer->getNextLayer();
    }

    // if layer was allocated by this packet and tryToDelete flag is set, delete
    // it
    if (tryToDelete && layer->m_IsAllocatedInPacket)
    {
        delete layer;
        delete[] layerOldData;
    }
    // if layer was not allocated by this packet or the tryToDelete is not set,
    // detach it from the packet so it can be reused
    else
    {
        layer->m_Packet = nullptr;
        layer->m_Data = layerOldData;
        layer->m_DataLen = layerOldDataSize;
    }

    return true;
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

std::string Packet::printPacketInfo(bool timeAsLocalTime) const
{
    std::ostringstream dataLenStream;
    dataLenStream << m_RawDataLen;

    // convert raw packet timestamp to printable format
    timespec timestamp = m_TimeStamp;
    time_t nowtime = timestamp.tv_sec;
    struct tm* nowtm = nullptr;
#if __cplusplus > 199711L && !defined(_WIN32)
    // localtime_r and gmtime_r are thread-safe versions of localtime and
    // gmtime, but they're defined only in newer compilers (>= C++0x). on
    // Windows localtime and gmtime are already thread-safe so there is not need
    // to use localtime_r and gmtime_r
    struct tm nowtm_r;
    if (timeAsLocalTime)
        nowtm = localtime_r(&nowtime, &nowtm_r);
    else
        nowtm = gmtime_r(&nowtime, &nowtm_r);

    if (nowtm != nullptr)
        nowtm = &nowtm_r;
#else
    // on Window compilers localtime and gmtime are already thread safe.
    // in old compilers (< C++0x) gmtime_r and localtime_r were not defined so
    // we have to fall back to localtime and gmtime
    if (timeAsLocalTime)
        nowtm = localtime(&nowtime);
    else
        nowtm = gmtime(&nowtime);
#endif

    char buf[128];
    if (nowtm != nullptr)
    {
        char tmbuf[64];
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
        snprintf(buf, sizeof(buf), "%s.%09lu", tmbuf, (unsigned long)timestamp.tv_nsec);
    }
    else
        snprintf(buf, sizeof(buf), "0000-00-00 00:00:00.000000000");

    return "Packet length: " + dataLenStream.str() + " [Bytes], Arrival time: " + std::string(buf);
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

std::string Packet::toString(bool timeAsLocalTime) const
{
    std::vector<std::string> stringList;
    toStringList(stringList, timeAsLocalTime);
    return std::accumulate(stringList.begin(), stringList.end(), std::string(),
                           [](std::string a, const std::string& b) { return std::move(a) + b + '\n'; });
}

void Packet::toStringList(std::vector<std::string>& result, bool timeAsLocalTime) const
{
    result.clear();
    result.push_back(printPacketInfo(timeAsLocalTime));
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
