#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string>

#include <casket/nonstd/optional.hpp>
#include <casket/nonstd/span.hpp>
#include <snet/layers/protocol.hpp>

namespace snet::layers
{

struct LayerInfo
{
    ProtocolType protocol;
    uint32_t offset;
    uint16_t headerLength;
    uint16_t payloadOffset;

    uint32_t getEndOffset() const noexcept
    {
        return offset + headerLength;
    }
};

/**
 * @class IDataContainer
 * An interface (virtual abstract class) that indicates an object that holds a pointer to a buffer data. The Layer
 * class is an example of such object, hence it inherits this interface
 */
class IDataContainer
{
public:
    /**
     * Get a pointer to the data
     * @param[in] offset Get a pointer in a certain offset. Default is 0 - get a pointer to start of data
     * @return A pointer to the data
     */
    virtual uint8_t* getDataPtr(size_t offset = 0) const = 0;

    virtual ~IDataContainer() = default;
};

} // namespace snet::layers
