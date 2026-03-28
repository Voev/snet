#pragma once
#include <memory>
#include <functional>
#include <string>
#include <string_view>
#include <array>

#include <snet/io/types.hpp>
#include <snet/io/dynamic_library.hpp>
#include <snet/io/driver_config.hpp>

#include <snet/layers/link_type.hpp>
#include <snet/layers/packet.hpp>
#include <snet/layers/packet_pool.hpp>

namespace snet::io
{

using DriverError = std::array<char, 256>;  ///< Buffer for error messages.

/// @brief Abstract base class for network drivers.
class Driver
{
public:
    Driver() = default;

    virtual ~Driver() noexcept = default;

    /// @brief Gets driver name.
    /// @return Driver identifier string.
    virtual const char* getName() const = 0;

    /// @brief Configures driver with specified parameters.
    /// @param[in] config Configuration parameters.
    /// @return Status indicating success or failure.
    virtual Status configure(const Config& config) = 0;

    /// @brief Starts driver operation.
    /// @return Status indicating success or failure.
    virtual Status start() = 0;

    /// @brief Stops driver operation.
    /// @return Status indicating success or failure.
    virtual Status stop() = 0;

    /// @brief Injects raw packet.
    /// @param[in] data Packet data buffer.
    /// @param[in] data_len Buffer length in bytes.
    /// @return Status indicating success or failure.
    virtual Status inject(const uint8_t* data, uint32_t data_len) = 0;

    /// @brief Interrupts ongoing operations.
    /// @return Status indicating success or failure.
    virtual Status interrupt() = 0;

    /// @brief Gets driver statistics.
    /// @param[out] stats Structure to fill with statistics.
    /// @return Status indicating success or failure.
    virtual Status getStats(Stats* stats) = 0;

    /// @brief Resets all statistics counters.
    virtual void resetStats() = 0;

    /// @brief Gets snapshot length.
    /// @return Maximum captured packet length in bytes.
    virtual int getSnaplen() const = 0;

    /// @brief Gets link layer type.
    /// @return LinkLayerType enumeration value.
    virtual layers::LinkLayerType getDataLinkType() const = 0;

    /// @brief Receives single packet.
    /// @param[out] rawPacket Pointer to receive captured packet.
    /// @return RecvStatus indicating result.
    virtual RecvStatus receivePacket(layers::Packet** rawPacket) = 0;

    /// @brief Receives multiple packets.
    /// @param[out] rawPacket Array of packet pointers.
    /// @param[in,out] packetCount On input: max packets; on output: actual received.
    /// @param[in] maxCount Maximum packets to receive.
    /// @return RecvStatus indicating result.
    virtual RecvStatus receivePackets(layers::Packet** rawPacket, uint16_t* packetCount, uint16_t maxCount) = 0;

    /// @brief Finalizes packet with verdict.
    /// @param[in] rawPacket Packet to finalize.
    /// @param[in] verdict Processing decision.
    /// @return Status indicating success or failure.
    virtual Status finalizePacket(layers::Packet* rawPacket, Verdict verdict) = 0;

    /// @brief Gets packet pool information.
    /// @param[out] info Structure to fill with pool statistics.
    /// @return Status indicating success or failure.
    virtual Status getMsgPoolInfo(layers::PacketPoolInfo& info) = 0;

    /// @brief Gets last error message.
    /// @return Pointer to error string buffer.
    const char* getLastError() const
    {
        return error_.data();
    }

protected:
    /// @brief Sets error message.
    /// @param[in] msg Error message string.
    void setError(std::string_view msg)
    {
        strncpy(error_.data(), msg.empty() ? "" : msg.data(), error_.size() - 1);
        error_.back() = '\0';
    }

protected:
    DriverError error_;  ///< Error message buffer.
};

/// @brief Driver creation function type.
using DriverCreator = std::shared_ptr<Driver>(const DriverConfig&);

} // namespace snet::io