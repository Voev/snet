#pragma once
#include <array>
#include <string>
#include <cstdint>

#include <snet/io/device.hpp>

#include "afpacket_types.hpp"
#include "afpacket_fanout.hpp"

#include <snet/layers/l2/mac_address.hpp>

namespace snet::driver
{

class AFPacketDriver;

/// @brief Single AF_PACKET socket instance bound to a network interface.
///
/// Manages the underlying socket, RX/TX rings, and provides packet
/// reception and transmission for one network device.
class Instance final : public io::Device
{
public:
    /// @brief Constructs an instance owned by the given driver.
    /// @param[in] driver Owning driver.
    /// @param[in] id Unique device identifier.
    explicit Instance(AFPacketDriver& driver, io::DeviceId id);

    /// @brief Destructor. Releases rings and closes the socket.
    ~Instance() noexcept;

    /// @brief Deleted copy constructor.
    Instance(const Instance&) = delete;

    /// @brief Deleted copy assignment operator.
    Instance& operator=(const Instance&) = delete;

    /// @brief Gets device identifier.
    /// @return Unique device identifier.
    io::DeviceId id() const noexcept override
    {
        return id_;
    }

    /// @brief Gets device name.
    /// @return Interface name.
    const std::string& name() const noexcept override
    {
        return name_;
    }

    /// @brief Gets interface index.
    /// @return Kernel interface index.
    uint32_t ifindex() const noexcept override
    {
        return index_;
    }

    /// @brief Gets MAC address.
    /// @return Device MAC address.
    const layers::MacAddress& mac() const noexcept override
    {
        return mac_;
    }

    /// @brief Gets MTU.
    /// @return Maximum transmission unit in bytes.
    uint32_t mtu() const noexcept override
    {
        return mtu_;
    }

    /// @brief Gets effective snapshot length.
    /// @return Actual capture snapshot length in bytes.
    uint32_t snaplen() const noexcept override
    {
        return actualSnaplen_;
    }

    /// @brief Checks whether the interface is up.
    /// @return True if the interface is up.
    bool up() const noexcept override
    {
        return up_;
    }

    /// @brief Gets underlying socket file descriptor.
    /// @return Socket file descriptor, or -1 if not opened.
    int fd() const noexcept
    {
        return fd_;
    }

    /// @brief Sends raw data through this instance.
    /// @param[in] data Pointer to the data buffer.
    /// @param[in] length Number of bytes to send.
    /// @return True on success, false otherwise.
    bool send(const uint8_t* data, size_t length) noexcept override;

    /// @brief Creates the socket and binds it to the named interface.
    /// @param[in] name Interface name.
    /// @return True on success, false otherwise.
    bool create(const std::string& name);

    /// @brief Destroys the socket and releases all resources.
    void destroy();

    /// @brief Ring configuration parameters.
    struct RingConfig
    {
        uint32_t ringSizeHint{0}; ///< Requested ring size hint (number of frames).
        uint32_t snaplen{0};      ///< Snapshot length in bytes.
        bool useTxRing{false};    ///< Whether to set up a TX ring.
    };

    /// @brief Creates RX (and optionally TX) rings.
    /// @param[in] cfg Ring configuration.
    /// @return True on success, false otherwise.
    bool createRings(const RingConfig& cfg);

    /// @brief Binds the socket to a specific protocol.
    /// @param[in] protocol Protocol number (e.g. ETH_P_ALL).
    /// @return True on success, false otherwise.
    bool bindTo(int protocol);

    /// @brief Enables packet fanout with the given mode and flags.
    /// @param[in] fanoutType Fanout hashing mode.
    /// @param[in] fanoutFlags Fanout behavior flags.
    /// @return True on success, false otherwise.
    bool configureFanout(afpacket::Fanout::Type fanoutType, afpacket::Fanout::Flags fanoutFlags);

    /// @brief Status of a receive attempt.
    enum class RxStatus
    {
        Ok,       ///< Frame was successfully received.
        NoPacket, ///< No packet available.
        Corrupt   ///< Frame was corrupt or invalid.
    };

    /// @brief Received frame descriptor.
    struct RxFrame
    {
        uint8_t* data{nullptr}; ///< Pointer to frame payload.
        uint32_t caplen{0};     ///< Captured length in bytes.
        uint32_t len{0};        ///< Original wire length in bytes.
        RingEntry* entry{nullptr}; ///< Associated ring entry for release.
    };

    /// @brief Receives a single frame from the RX ring.
    /// @param[out] out Received frame descriptor.
    /// @return Receive status.
    RxStatus receive(RxFrame& out) noexcept;

    /// @brief Releases a previously received frame back to the ring.
    /// @param[in] entry Ring entry to release.
    void releaseFrame(RingEntry* entry) noexcept;

    /// @brief Releases all outstanding frames held by the caller.
    void releaseOutstandingFrames() noexcept;

    /// @brief Gets number of frames in the RX ring.
    /// @return RX ring frame count.
    uint32_t rxFrameCount() const noexcept
    {
        return rxRing_.layout.tp_frame_nr;
    }

    const layers::MacAddress& mac() const noexcept
    {
        return mac_;
    }

    [[nodiscard]] uint32_t ip() const noexcept
    {
        return ip_;
    }

    [[nodiscard]] uint32_t netmask() const noexcept
    {
        return netmask_;
    }

private:
    /// @brief Computes the per-frame size for the given snaplen.
    /// @param[in] snaplen Snapshot length in bytes.
    /// @return True on success, false otherwise.
    bool calculateFrameSize(uint32_t snaplen);

    /// @brief Computes the ring layout for a given order.
    /// @param[out] layout Computed tpacket request layout.
    /// @param[in] order Allocation order (power-of-two page count).
    /// @return True on success, false otherwise.
    bool calculateLayout(tpacket_req& layout, int order) const;

    /// @brief Creates the RX ring.
    /// @return True on success, false otherwise.
    bool createRxRing();

    /// @brief Creates the TX ring.
    /// @return True on success, false otherwise.
    bool createTxRing();

    /// @brief Maps ring buffers into userspace.
    /// @return True on success, false otherwise.
    bool mmapRings();

    /// @brief Sets up the given ring for use.
    /// @param[in,out] ring Ring to set up.
    /// @return True on success, false otherwise.
    bool setupRing(Ring& ring);

    /// @brief Sends data using the TX ring.
    /// @param[in] data Pointer to the data buffer.
    /// @param[in] length Number of bytes to send.
    /// @return True on success, false otherwise.
    bool sendRing(const uint8_t* data, size_t length) noexcept;

    /// @brief Sends data directly via sendto().
    /// @param[in] data Pointer to the data buffer.
    /// @param[in] length Number of bytes to send.
    /// @return True on success, false otherwise.
    bool sendDirect(const uint8_t* data, size_t length) noexcept;

private:
    AFPacketDriver& driver_;      ///< Owning driver.
    io::DeviceId id_{io::kInvalidDevice}; ///< Device identifier.
    layers::MacAddress mac_{};    ///< Device MAC address.
    std::string name_;            ///< Interface name.
    int fd_{-1};                  ///< Socket file descriptor.
    uint32_t index_{0};           ///< Kernel interface index.
    uint32_t tpReserve_{0};       ///< TPACKET reserve size.
    uint32_t tpFrameSize_{0};     ///< TPACKET frame size.
    uint32_t tpHdrlen_{0};        ///< TPACKET header length.
    uint32_t actualSnaplen_{0};   ///< Effective snapshot length.
    uint32_t ringSizeHint_{0};    ///< Ring size hint.
    uint32_t snaplenCfg_{0};      ///< Configured snapshot length.
    uint32_t mtu_{0};             ///< Interface MTU.
    uint32_t macoff_{0};          ///< Offset to MAC header in frames.
    bool up_{false};              ///< Whether the interface is up.
    bool useTxRing_{false};       ///< Whether TX ring is used.
    void* buffer_{nullptr};       ///< Mapped ring buffer base.
    Ring rxRing_{};               ///< RX ring state.
    Ring txRing_{};               ///< TX ring state.
};

} // namespace snet::driver