#pragma once
#include <snet/layers/layer.hpp>

namespace snet::layers
{

/// @brief Represents a generic or unknown layer or a packet payload
class PayloadLayer : public Layer
{
public:
    /// @brief Constructor that creates the layer from an existing packet raw data
    /// @param[in] data A pointer to the raw data
    /// @param[in] dataLen Size of the data in bytes
    /// @param[in] prevLayer A pointer to the previous layer
    /// @param[in] packet A pointer to the Packet instance where layer will be stored in
    PayloadLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
        : Layer(data, dataLen, prevLayer, packet, GenericPayload)
    {
    }

    /// Constructor that allocates a new payload
    /// @param[in] data A raw buffer that will be used as a payload. This data
    /// will be copied to the layer
    /// @param[in] dataLen The raw buffer length
    PayloadLayer(const uint8_t* data, size_t dataLen);

    /// @brief Default destructor.
    ~PayloadLayer() override = default;

    /// Sets the payload of the PayloadLayer to the given pointer. This will
    /// resize (extend/shorten) the underlying packet respectively if there is
    /// one.
    /// @param[in] newPayload New payload that shall be set
    /// @param[in] newPayloadLength New length of payload
    void setPayload(const uint8_t* newPayload, size_t newPayloadLength);

    /// Get a pointer to the payload data
    /// @return A pointer to the payload data
    uint8_t* getPayload() const
    {
        return m_Data;
    }

    /// Get the payload data length
    /// @return The payload data length in bytes
    size_t getPayloadLen() const
    {
        return m_DataLen;
    }

    /// Does nothing for this layer (PayloadLayer is always last)
    void parseNextLayer() override
    {
    }

    /// @return Payload data length in bytes
    size_t getHeaderLen() const override
    {
        return m_DataLen;
    }

    /// Does nothing for this layer
    void computeCalculateFields() override
    {
    }

    std::string toString() const override;

    /// @brief Gets application layer for OSI model.
    /// @return Application layer enum type.
    OsiModelLayer getOsiModelLayer() const override
    {
        return OsiModelApplicationLayer;
    }
};

} // namespace snet::layers
