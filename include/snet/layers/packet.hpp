#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>
#include <vector>
#include <casket/nonstd/span.hpp>

#include <snet/layers/link_type.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>
#include <snet/layers/timestamp.hpp>

namespace snet::layers
{

class Packet
{
    friend class Layer;

private:
    Timestamp timestamp_;

    uint8_t* m_RawData{nullptr};
    Layer* m_FirstLayer{nullptr};
    Layer* m_LastLayer{nullptr};

    size_t m_RawDataLen{0UL};
    size_t m_MaxPacketLen{0UL};
    size_t m_FrameLength{0UL};

    LinkLayerType m_LinkLayerType{LINKTYPE_ETHERNET};

    bool m_CanReallocateData{false};
    bool m_DeleteRawDataAtDestructor{false};

public:
    Packet();

    virtual ~Packet() noexcept;

    Packet(nonstd::span<const uint8_t> data, bool deleteRawDataAtDestructor,
           LinkLayerType layerType = LINKTYPE_ETHERNET);

    Packet(size_t maxPacketLen);

    Packet(nonstd::span<uint8_t> buffer);

    Packet(const Packet& other) = delete;

    Packet& operator=(const Packet& other) = delete;

    void clear();

    virtual void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

    virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

    virtual bool removeData(size_t atIndex, size_t numOfBytesToRemove);

    virtual bool reallocateData(size_t newBufferLength);

    virtual bool setRawData(nonstd::span<const uint8_t> data, LinkLayerType layerType, int frameLength);

    void setTimestamp(Timestamp timestamp)
    {
        timestamp_ = std::move(timestamp);
    }

    Timestamp getTimestamp() const
    {
        return timestamp_;
    }

    const uint8_t* getData() const
    {
        return m_RawData;
    }

    LinkLayerType getLinkLayerType() const
    {
        return m_LinkLayerType;
    }

    size_t getDataLen() const
    {
        return m_RawDataLen;
    }

    void parsePacket(ProtocolTypeFamily parseUntil = UnknownProtocol,
                     OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

    /**
     * Get a pointer to the first (lowest) layer in the packet
     * @return A pointer to the first (lowest) layer in the packet
     */
    Layer* getFirstLayer() const
    {
        return m_FirstLayer;
    }

    /**
     * Get a pointer to the last (highest) layer in the packet
     * @return A pointer to the last (highest) layer in the packet
     */
    Layer* getLastLayer() const
    {
        return m_LastLayer;
    }

    /**
     * Get a pointer to the layer of a certain type (protocol). This method goes through the layers and returns a
     * layer that matches the give protocol type
     * @param[in] layerType The layer type (protocol) to fetch
     * @param[in] index If there are multiple layers of the same type, indicate which instance to fetch. The default
     * value is 0, meaning fetch the first layer of this type
     * @return A pointer to the layer or nullptr if no such layer was found
     */
    Layer* getLayerOfType(ProtocolType layerType, int index = 0) const;

    /**
     * A templated method to get a layer of a certain type (protocol). If no layer of such type is found, nullptr is
     * returned
     * @param[in] reverseOrder The optional parameter that indicates that the lookup should run in reverse order,
     * the default value is false
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getLayerOfType(bool reverseOrder = false) const;

    /**
     * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
     * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
     * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3) will be
     * returned If no layer of such type is found, nullptr is returned
     * @param[in] startLayer A pointer to the layer to start search from
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getNextLayerOfType(Layer* startLayer) const;

    /**
     * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
     * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
     * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(1) will be
     * returned If no layer of such type is found, nullptr is returned
     * @param[in] startLayer A pointer to the layer to start search from
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getPrevLayerOfType(Layer* startLayer) const;

    /**
     * Check whether the packet contains a layer of a certain protocol
     * @param[in] protocolType The protocol type to search
     * @return True if the packet contains a layer of a certain protocol, false otherwise
     */
    bool isPacketOfType(ProtocolType protocolType) const;

    /**
     * Check whether the packet contains a layer of a certain protocol family
     * @param[in] protocolTypeFamily The protocol type family to search
     * @return True if the packet contains a layer of a certain protocol family, false otherwise
     */
    bool isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const;

    /**
     * Each layer can have fields that can be calculate automatically from other fields using
     * Layer#computeCalculateFields(). This method forces all layers to calculate these fields values
     */
    void computeCalculateFields();

    /**
     * Each layer can print a string representation of the layer most important data using Layer#toString(). This
     * method aggregates this string from all layers and print it to a complete string containing all packet's
     * relevant data
     * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
     * to false
     * @return A string containing most relevant data from all layers (looks like the packet description in
     * Wireshark)
     */
    std::string toString() const;

    /**
     * Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
     * @param[out] result A string vector that will contain all strings
     * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
     * to false
     */
    void toStringList(std::vector<std::string>& result) const;

    static bool isLinkTypeValid(int linkTypeValue);

private:
    void destructPacketData();

    bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
    bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

    void reallocateRawData(size_t newSize);

    std::string printPacketInfo() const;

    Layer* createFirstLayer(layers::LinkLayerType linkType);

}; // class Packet

// implementation of inline methods

template <class TLayer>
TLayer* Packet::getLayerOfType(bool reverse) const
{
    if (!reverse)
    {
        if (dynamic_cast<TLayer*>(getFirstLayer()) != nullptr)
            return dynamic_cast<TLayer*>(getFirstLayer());

        return getNextLayerOfType<TLayer>(getFirstLayer());
    }

    // lookup in reverse order
    if (dynamic_cast<TLayer*>(getLastLayer()) != nullptr)
        return dynamic_cast<TLayer*>(getLastLayer());

    return getPrevLayerOfType<TLayer>(getLastLayer());
}

template <class TLayer>
TLayer* Packet::getNextLayerOfType(Layer* curLayer) const
{
    if (curLayer == nullptr)
        return nullptr;

    curLayer = curLayer->getNextLayer();
    while ((curLayer != nullptr) && (dynamic_cast<TLayer*>(curLayer) == nullptr))
    {
        curLayer = curLayer->getNextLayer();
    }

    return dynamic_cast<TLayer*>(curLayer);
}

template <class TLayer>
TLayer* Packet::getPrevLayerOfType(Layer* curLayer) const
{
    if (curLayer == nullptr)
        return nullptr;

    curLayer = curLayer->getPrevLayer();
    while (curLayer != nullptr && dynamic_cast<TLayer*>(curLayer) == nullptr)
    {
        curLayer = curLayer->getPrevLayer();
    }

    return dynamic_cast<TLayer*>(curLayer);
}

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::Packet& packet)
{
    os << packet.toString();
    return os;
}