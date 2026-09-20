#pragma once
#include <memory>
#include <functional>
#include <string>

#include <snet/io/types.hpp>
#include <snet/io/dynamic_library.hpp>
#include <snet/io/driver_config.hpp>
#include <snet/io/config.hpp>

#include <snet/layers/link_type.hpp>
#include <snet/layers/packet.hpp>

namespace snet::io
{

/// @brief Packet pool statistics information
struct PacketPoolInfo
{
    uint32_t capacity{0U};  ///< Total number of packets in the pool
    uint32_t available{0U}; ///< Number of free packets available for acquisition
    size_t memorySize{0U};  ///< Total memory allocated by the pool (objects + data buffers)

    /// @brief Prints pool statistics to the given stream.
    /// @param[in] os Output stream.
    void print(std::ostream& os) const
    {
        os << "Packet pool information:\n"
           << "  capacity:   " << capacity << "\n"
           << "  available:  " << available << "\n"
           << "  memorySize: " << memorySize << " bytes\n";
    }
};

/// @brief Stream operator for convenient logging.
inline std::ostream& operator<<(std::ostream& os, const PacketPoolInfo& info)
{
    info.print(os);
    return os;
}

/// @brief Abstract base class for network drivers.
class Driver
{
public:
    Driver() = default;

    virtual ~Driver() noexcept = default;

    /// @brief Gets driver name.
    /// @return Driver identifier string.
    virtual const char* getName() const = 0;

    /// @brief Registers driver-specific options in the shared config section.
    ///
    /// Called once by the controller before the config file is parsed.
    /// Add your options via Config::addDriverOption() using the names as they
    /// appear in the config file. Option names must be unique within the section.
    ///
    /// @param[out] config Shared driver configuration section.
    ///
    /// @return Status of the operation.
    virtual Status declareOptions(io::Config& config) = 0;

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
    virtual Status getMsgPoolInfo(PacketPoolInfo& info) = 0;
};

/// @brief Driver creation function type.
using DriverCreator = std::shared_ptr<Driver>(const DriverConfig&);

} // namespace snet::io