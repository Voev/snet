#pragma once
#include <memory>
#include <functional>
#include <string>

#include <snet/io/types.hpp>
#include <snet/io/dynamic_library.hpp>
#include <snet/io/driver_spec.hpp>
#include <snet/io/device.hpp>
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
/// @param[in] os Output stream.
/// @param[in] info Pool information to print.
/// @return Reference to the output stream.
inline std::ostream& operator<<(std::ostream& os, const PacketPoolInfo& info)
{
    info.print(os);
    return os;
}

/// @brief Abstract base class for network drivers.
class Driver
{
public:
    /// @brief Default constructor.
    Driver() = default;

    /// @brief Virtual destructor.
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

    /// @brief Interrupts ongoing operations.
    /// @return Status indicating success or failure.
    virtual Status interrupt() = 0;

    /// @brief Gets number of devices.
    /// @return Number of available devices.
    virtual size_t deviceCount() const = 0;

    /// @brief Gets device by index.
    /// @param[in] idx Device index.
    /// @return Pointer to the device, or nullptr if idx is invalid.
    virtual io::Device* deviceAt(size_t idx) const = 0;

    /// @brief  Received packet descriptor.
    struct RxItem
    {
        layers::Packet* packet{nullptr};  ///< Received packet.
        io::DeviceId ingress{io::kInvalidDevice}; ///< Ingress device identifier.
    };

    /// @brief Receives packets from the driver.
    /// @param[out] rx Array to fill with received packet items.
    /// @param[out] count Number of packets actually received.
    /// @param[in] max Maximum number of packets to receive.
    /// @return Receive status.
    virtual RecvStatus receivePackets(RxItem* rx, uint16_t* count, uint16_t max) = 0;

    /// @brief Finalizes packet with verdict.
    /// @param[in] packet Packet to finalize.
    /// @param[in] verdict Processing decision.
    /// @return Status indicating success or failure.
    virtual Status finalizePacket(layers::Packet* packet, Verdict verdict) = 0;

    /// @brief Transmits a packet through the specified egress device.
    /// @param[in] packet Packet to transmit.
    /// @param[in] egress Egress device identifier.
    /// @return Status indicating success or failure.
    virtual Status transmitPacket(layers::Packet* packet, io::DeviceId egress) = 0;

    /// @brief Gets packet pool information.
    /// @param[out] info Structure to fill with pool statistics.
    /// @return Status indicating success or failure.
    virtual Status getMsgPoolInfo(PacketPoolInfo& info) = 0;

    /// @brief Gets driver statistics.
    /// @param[out] stats Structure to fill with statistics.
    /// @return Status indicating success or failure.
    virtual Status getStats(Stats* stats) = 0;

    /// @brief Resets all statistics counters.
    virtual void resetStats() = 0;

    /// @brief Gets link layer type.
    /// @return LinkLayerType enumeration value.
    virtual layers::LinkLayerType getDataLinkType() const = 0;
};

/// @brief Driver creation function type.
using DriverCreator = std::shared_ptr<Driver>(const DriverSpec&);

} // namespace snet::io