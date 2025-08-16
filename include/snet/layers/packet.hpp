#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>
#include <vector>

#include <snet/layers/link_type.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

class Packet
{
    friend class Layer;

private:
    timespec m_TimeStamp;

    uint8_t* m_RawData{nullptr};
    Layer* m_FirstLayer{nullptr};
    Layer* m_LastLayer{nullptr};

    size_t m_RawDataLen{0UL};
    size_t m_MaxPacketLen{0UL};
    size_t m_FrameLength{0UL};

    LinkLayerType m_LinkLayerType{LINKTYPE_ETHERNET};

    bool m_CanReallocateData{false};
    bool m_DeleteRawDataAtDestructor{false};
    bool m_RawPacketSet{false};

public:
    Packet();

    virtual ~Packet() noexcept;

    Packet(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor,
           LinkLayerType layerType = LINKTYPE_ETHERNET);

    Packet(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
           LinkLayerType layerType = LINKTYPE_ETHERNET);

    Packet(size_t maxPacketLen);

    Packet(uint8_t* buffer, size_t bufferSize);

    Packet(const Packet& other);

    Packet& operator=(const Packet& other);

    Packet* clone() const;

    void clear();

    virtual void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

    virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

    virtual bool removeData(size_t atIndex, size_t numOfBytesToRemove);

    virtual bool reallocateData(size_t newBufferLength);

    virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp,
                            LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

    virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType,
                            int frameLength);

    virtual bool setPacketTimeStamp(timeval timestamp);

    virtual bool setPacketTimeStamp(timespec timestamp);

    timespec getTimeStamp() const
    {
        return m_TimeStamp;
    }

    void parsePacket(ProtocolTypeFamily parseUntil = UnknownProtocol,
                     OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

    void copyDataFrom(const Packet& other, bool allocateData);

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
     * Add a new layer as the last layer in the packet. This method gets a pointer to the new layer as a parameter
     * and attaches it to the packet. Notice after calling this method the input layer is attached to the packet so
     * every change you make in it affect the packet; Also it cannot be attached to other packets
     * @param[in] newLayer A pointer to the new layer to be added to the packet
     * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default
     * is false.
     * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
     * such cases)
     */
    bool addLayer(Layer* newLayer, bool ownInPacket = false)
    {
        return insertLayer(m_LastLayer, newLayer, ownInPacket);
    }

    /**
     * Insert a new layer after an existing layer in the packet. This method gets a pointer to the new layer as a
     * parameter and attaches it to the packet. Notice after calling this method the input layer is attached to the
     * packet so every change you make in it affect the packet; Also it cannot be attached to other packets
     * @param[in] prevLayer A pointer to an existing layer in the packet which the new layer should followed by. If
     * this layer isn't attached to a packet and error will be printed to log and false will be returned
     * @param[in] newLayer A pointer to the new layer to be added to the packet
     * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default
     * is false.
     * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
     * such cases)
     */
    bool insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket = false);

    /**
     * Remove an existing layer from the packet. The layer to removed is identified by its type (protocol). If the
     * packet has multiple layers of the same type in the packet the user may specify the index of the layer to
     * remove (the default index is 0 - remove the first layer of this type). If the layer was allocated during
     * packet creation it will be deleted and any pointer to it will get invalid. However if the layer was allocated
     * by the user and manually added to the packet it will simply get detached from the packet, meaning the pointer
     * to it will stay valid and its data (that was removed from the packet) will be copied back to the layer. In
     * that case it's the user's responsibility to delete the layer instance
     * @param[in] layerType The layer type (protocol) to remove
     * @param[in] index If there are multiple layers of the same type, indicate which instance to remove. The
     * default value is 0, meaning remove the first layer of this type
     * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
     * such cases)
     */
    bool removeLayer(ProtocolType layerType, int index = 0);

    /**
     * Remove the first layer in the packet. The layer will be deleted if it was allocated during packet creation,
     * or detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
     * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
     * in the packet. In any case of failure an appropriate error log message will be printed
     */
    bool removeFirstLayer();

    /**
     * Remove the last layer in the packet. The layer will be deleted if it was allocated during packet creation, or
     * detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
     * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
     * in the packet. In any case of failure an appropriate error log message will be printed
     */
    bool removeLastLayer();

    /**
     * Remove all layers that come after a certain layer. All layers removed will be deleted if they were allocated
     * during packet creation or detached if were allocated outside of the packet, please refer to removeLayer() to
     * get more info
     * @param[in] layer A pointer to the layer to begin removing from. Please note this layer will not be removed,
     * only the layers that come after it will be removed. Also, if removal of one layer failed, the method will
     * return immediately and the following layers won't be deleted
     * @return True if all layers were removed successfully, or false if failed to remove at least one layer. In any
     * case of failure an appropriate error log message will be printed
     */
    bool removeAllLayersAfter(Layer* layer);

    /**
     * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
     * from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
     * the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
     * packet (but it's impossible to attach a layer to multiple packets in the same time). After layer is detached,
     * it's the user's responsibility to delete it when it's not needed anymore
     * @param[in] layerType The layer type (protocol) to detach from the packet
     * @param[in] index If there are multiple layers of the same type, indicate which instance to detach. The
     * default value is 0, meaning detach the first layer of this type
     * @return A pointer to the detached layer or nullptr if detaching process failed. In any case of failure an
     * appropriate error log message will be printed
     */
    Layer* detachLayer(ProtocolType layerType, int index = 0);

    /**
     * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
     * from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
     * the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
     * packet (but it's impossible to attach a layer to multiple packets at the same time). After layer is detached,
     * it's the user's responsibility to delete it when it's not needed anymore
     * @param[in] layer A pointer to the layer to detach
     * @return True if the layer was detached successfully, or false if something went wrong. In any case of failure
     * an appropriate error log message will be printed
     */
    bool detachLayer(Layer* layer)
    {
        return removeLayer(layer, false);
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
    std::string toString(bool timeAsLocalTime = true) const;

    /**
     * Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
     * @param[out] result A string vector that will contain all strings
     * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
     * to false
     */
    void toStringList(std::vector<std::string>& result, bool timeAsLocalTime = true) const;

    static bool isLinkTypeValid(int linkTypeValue);

private:
    void copyDataFrom(const Packet& other);

    void destructPacketData();

    bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
    bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

    void reallocateRawData(size_t newSize);

    bool removeLayer(Layer* layer, bool tryToDelete);

    std::string printPacketInfo(bool timeAsLocalTime) const;

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