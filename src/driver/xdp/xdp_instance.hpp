#pragma once

#include <cstdint>
#include <string>

#include <xdp/xsk.h>
#include <snet/io/device.hpp>

namespace snet::driver
{

class XdpDriver;

/// @brief Per-queue AF_XDP endpoint.
/// @details One instance == one (iface, queueId) pair == one AF_XDP socket registered
/// in the BPF program's XSKMAP under key = queueId.
class XdpInstance final : public io::Device
{
public:
    /// @brief Constructs an instance bound to a driver.
    /// @param[in] driver Reference to the owning XdpDriver.
    /// @param[in] id Device identifier.
    explicit XdpInstance(XdpDriver& driver, io::DeviceId id);

    /// @brief Destroys the instance and releases resources.
    ~XdpInstance() noexcept;

    /// @brief Copy construction is deleted.
    XdpInstance(const XdpInstance&) = delete;

    /// @brief Copy assignment is deleted.
    XdpInstance& operator=(const XdpInstance&) = delete;

    /// @brief Returns the device identifier.
    /// @return Device identifier.
    io::DeviceId id() const noexcept override
    {
        return id_;
    }

    /// @brief Returns the device name.
    /// @return Device name string.
    const std::string& name() const noexcept override
    {
        return name_;
    }

    /// @brief Returns the interface index.
    /// @return Interface index.
    uint32_t ifindex() const noexcept override
    {
        return ifindex_;
    }

    /// @brief Returns the device MAC address.
    /// @return MAC address.
    const layers::MacAddress& mac() const noexcept override
    {
        return mac_;
    }

    /// @brief Returns the interface MTU.
    /// @return MTU in bytes.
    uint32_t mtu() const noexcept override
    {
        return mtu_;
    }

    /// @brief Returns the snapshot length.
    /// @return Snaplen in bytes.
    uint32_t snaplen() const noexcept override
    {
        return snaplen_;
    }

    /// @brief Returns whether the device is up.
    /// @return True if active, false otherwise.
    bool up() const noexcept override
    {
        return active_;
    }

    /// @brief Sends raw Ethernet frame through this endpoint.
    /// @details Copies the payload into a UMEM frame and submits it to the
    /// TX ring. Not zero-copy on the userspace side, but that matches the
    /// intended use (userspace-generated frames: ACKs, resets, etc.).
    /// @param[in] data Pointer to the frame data.
    /// @param[in] length Frame length in bytes.
    /// @return True on success, false otherwise.
    bool send(const uint8_t* data, size_t length) noexcept override;

    /// @brief Configures the instance for the given interface and queue.
    /// @param[in] iface Interface name.
    /// @param[in] queueId Queue identifier.
    /// @return True on success, false otherwise.
    bool configure(const std::string& iface, uint32_t queueId);

    /// @brief Creates the AF_XDP socket and binds its rings.
    /// @param[in] umem UMEM handle shared across instances.
    /// @param[in] cfg Socket configuration.
    /// @return True on success, false otherwise.
    bool create(struct xsk_umem* umem, const struct xsk_socket_config& cfg);

    /// @brief Destroys the AF_XDP socket and releases resources.
    void destroy() noexcept;

    /// @brief Returns the RX ring consumer.
    /// @return Pointer to the RX ring.
    struct xsk_ring_cons* rxRing() noexcept
    {
        return &rx_;
    }

    /// @brief Returns the TX ring producer.
    /// @return Pointer to the TX ring.
    struct xsk_ring_prod* txRing() noexcept
    {
        return &tx_;
    }

    /// @brief Returns the fill ring producer.
    /// @return Pointer to the fill ring.
    struct xsk_ring_prod* fqRing() noexcept
    {
        return &fq_;
    }

    /// @brief Returns the completion ring consumer.
    /// @return Pointer to the completion ring.
    struct xsk_ring_cons* cqRing() noexcept
    {
        return &cq_;
    }

    /// @brief Returns the socket file descriptor.
    /// @return Socket fd, or -1 if not created.
    int fd() const noexcept
    {
        return fd_;
    }

    /// @brief Returns the queue identifier.
    /// @return Queue identifier.
    uint32_t queueId() const noexcept
    {
        return queueId_;
    }

    /// @brief Returns whether the instance is active.
    /// @return True if active, false otherwise.
    bool active() const noexcept
    {
        return active_;
    }

    /// @brief Refills the fill queue from the driver's free-frame pool.
    /// @param[in] max Maximum number of frames to enqueue.
    /// @return Number of frames actually enqueued.
    uint32_t refillFq(uint32_t max);

    /// @brief Reclaims completed TX frames back to the driver's pool.
    /// @param[in] max Maximum number of completions to process.
    /// @return Number of frames reclaimed.
    uint32_t processCq(uint32_t max);

    /// @brief Kicks the TX ring if the kernel asked for a wakeup.
    /// @return True if a wakeup was issued, false otherwise.
    bool kickTx();

    /// @brief Transmits a single UMEM frame through this endpoint's TX ring.
    /// @param[in] frameAddr UMEM frame address.
    /// @param[in] len Frame length in bytes.
    /// @return True on success, false otherwise.
    bool transmit(uint64_t frameAddr, uint32_t len);

private:
    XdpDriver& driver_;            ///< Reference to the owning driver.
    io::DeviceId id_;              ///< Device identifier.

    std::string name_;             ///< Device name.
    uint32_t queueId_{0};          ///< Queue identifier.
    uint32_t ifindex_{0};          ///< Interface index.
    int fd_{-1};                   ///< Socket file descriptor.
    bool active_{false};           ///< Whether the instance is active.

    layers::MacAddress mac_{};     ///< Device MAC address.
    uint32_t mtu_{0};              ///< Interface MTU.
    uint32_t snaplen_{0};          ///< Snapshot length.

    struct xsk_socket* xsk_{nullptr}; ///< AF_XDP socket handle.
    struct xsk_ring_cons rx_{};    ///< RX ring consumer.
    struct xsk_ring_prod tx_{};    ///< TX ring producer.
    struct xsk_ring_prod fq_{};    ///< Fill ring producer.
    struct xsk_ring_cons cq_{};    ///< Completion ring consumer.
};

} // namespace snet::driver