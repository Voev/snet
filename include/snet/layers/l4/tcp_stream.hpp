#pragma once
#include <chrono>
#include <cstdint>

namespace snet::layers
{

class ConnectionInfo;

/**
 * @class TcpStreamData
 * When following a TCP connection each packet may contain a piece of the data
 * transferred between the client and the server. This class represents these
 * pieces: each instance of it contains a piece of data, usually extracted from
 * a single packet, as well as information about the connection
 */
class TcpStreamData
{
public:
    /**
     * A c'tor for this class that get data from outside and set the internal
     * members
     * @param[in] tcpData A pointer to buffer containing the TCP data piece
     * @param[in] tcpDataLength The length of the buffer
     * @param[in] missingBytes The number of missing bytes due to packet loss.
     * @param[in] connData TCP connection information for this TCP data
     * @param[in] timestamp when this packet was received
     */
    TcpStreamData(const uint8_t* tcpData, size_t tcpDataLength, size_t missingBytes, const ConnectionInfo& connData,
                  std::chrono::time_point<std::chrono::high_resolution_clock> timestamp)
        : data_(tcpData)
        , dataLength_(tcpDataLength)
        , missingBytes_(missingBytes)
        , connection_(connData)
        , timestamp_(timestamp)
    {
    }

    /**
     * A getter for the data buffer
     * @return A pointer to the buffer
     */
    const uint8_t* getData() const
    {
        return data_;
    }

    /**
     * A getter for buffer length
     * @return Buffer length
     */
    size_t getDataLength() const
    {
        return dataLength_;
    }

    /**
     * A getter for missing byte count due to packet loss.
     * @return Missing byte count
     */
    size_t getMissingByteCount() const
    {
        return missingBytes_;
    }

    /**
     * Determine if bytes are missing. getMissingByteCount can be called to
     * determine the number of missing bytes.
     * @return true if bytes are missing.
     */
    bool isBytesMissing() const
    {
        return getMissingByteCount() > 0;
    }

    /**
     * A getter for the connection data
     * @return The const reference to connection data
     */
    const ConnectionInfo& getConnectionData() const
    {
        return connection_;
    }

    /**
     * @return A nanosecond precision of the packet timestamp
     */
    std::chrono::time_point<std::chrono::high_resolution_clock> getTimeStampPrecise() const
    {
        return timestamp_;
    }

private:
    const uint8_t* data_;
    size_t dataLength_;
    size_t missingBytes_;
    const ConnectionInfo& connection_;
    std::chrono::time_point<std::chrono::high_resolution_clock> timestamp_;
};

}