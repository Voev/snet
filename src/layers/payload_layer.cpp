#include <cstring>
#include <sstream>
#include <snet/layers/payload_layer.hpp>
#include <casket/utils/hexlify.hpp>

namespace snet::layers
{

PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen)
    : Layer()
{
    m_Data = new uint8_t[dataLen];
    std::memcpy(m_Data, data, dataLen);
    m_DataLen = dataLen;
    m_Protocol = GenericPayload;
}

void PayloadLayer::setPayload(const uint8_t* newPayload, size_t newPayloadLength)
{
    if (newPayloadLength < m_DataLen)
    {
        // shorten payload layer
        shortenLayer(newPayloadLength, m_DataLen - newPayloadLength);
    }
    else if (newPayloadLength > m_DataLen)
    {
        // extend payload layer
        extendLayer(m_DataLen, newPayloadLength - m_DataLen);
    }

    // and copy data to layer
    // this is also executed if the newPayloadLength == m_DataLen
    std::memcpy(m_Data, newPayload, newPayloadLength);
}

std::string PayloadLayer::toString() const
{
    std::ostringstream dataLenStream;
    dataLenStream << m_DataLen;

    return "Payload Layer, Data length: " + dataLenStream.str() + " [Bytes]";
}

} // namespace snet::layers
