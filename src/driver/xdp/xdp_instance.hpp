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
    explicit XdpInstance(XdpDriver& driver, io::DeviceId id);

    /// @brief Destroys the instance and releases resources.
    ~XdpInstance() noexcept;

    /// @brief Copy construction is deleted.
    XdpInstance(const XdpInstance&) = delete;

    /// @brief Copy assignment is deleted.
    XdpInstance& operator=(const XdpInstance&) = delete;

    io::DeviceId id() const noexcept override
    {
        return id_;
    }

    const std::string& name() const noexcept override
    {
        return name_;
    }
    
    uint32_t ifindex() const noexcept override
    {
        return ifindex_;
    }
    
    const layers::MacAddress& mac() const noexcept override
    {
        return mac_;
    }
    
    uint32_t mtu() const noexcept override
    {
        return mtu_;
    }
    
    uint32_t snaplen() const noexcept override
    {
        return snaplen_;
    }
    
    bool up() const noexcept override
    {
        return active_;
    }

    /// @brief Sends raw Ethernet frame through this endpoint.
    /// @details Copies the payload into a UMEM frame and submits it to the
    /// TX ring. Not zero-copy on the userspace side, but that matches the
    /// intended use (userspace-generated frames: ACKs, resets, etc.).
    bool send(const uint8_t* data, size_t length) noexcept override;

    bool create(const std::string& iface, uint32_t queueId);

    bool bindTo(struct xsk_umem* umem, const struct xsk_socket_config& cfg);

    void destroy() noexcept;

    // ------------------------------------------------------------------
    // Ring access (used by XdpDriver for RX peeking)
    // ------------------------------------------------------------------

    struct xsk_ring_cons* rxRing() noexcept
    {
        return &rx_;
    }
    struct xsk_ring_prod* txRing() noexcept
    {
        return &tx_;
    }
    struct xsk_ring_prod* fqRing() noexcept
    {
        return &fq_;
    }
    struct xsk_ring_cons* cqRing() noexcept
    {
        return &cq_;
    }

    int fd() const noexcept
    {
        return fd_;
    }
    uint32_t queueId() const noexcept
    {
        return queueId_;
    }
    bool active() const noexcept
    {
        return active_;
    }
    void setActive(bool v) noexcept
    {
        active_ = v;
    }

    // ------------------------------------------------------------------
    // Ring I/O
    // ------------------------------------------------------------------

    /// @brief Refills the fill queue from the driver's free-frame pool.
    uint32_t refillFq(uint32_t max);

    /// @brief Reclaims completed TX frames back to the driver's pool.
    uint32_t processCq(uint32_t max);

    /// @brief Kicks the TX ring if the kernel asked for a wakeup.
    bool kickTx();

    /// @brief Transmits a single UMEM frame through this endpoint's TX ring.
    bool transmit(uint64_t frameAddr, uint32_t len);

private:
    XdpDriver& driver_;
    io::DeviceId id_;

    std::string name_;
    uint32_t queueId_{0};
    uint32_t ifindex_{0};
    int fd_{-1};
    bool active_{false};

    layers::MacAddress mac_{};
    uint32_t mtu_{0};
    uint32_t snaplen_{0};

    struct xsk_socket* xsk_{nullptr};
    struct xsk_ring_cons rx_{};
    struct xsk_ring_prod tx_{};
    struct xsk_ring_prod fq_{};
    struct xsk_ring_cons cq_{};
};

} // namespace snet::driver