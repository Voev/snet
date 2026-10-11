#pragma once

#include <cstdint>
#include <string>

#include <xdp/xsk.h>

namespace snet::driver
{

class XdpDriver;

/// @brief Per-queue AF_XDP endpoint.
/// @details One instance == one (iface, queueId) pair == one AF_XDP socket registered
/// in the BPF program's XSKMAP under key = queueId.
class XdpInstance final
{
public:
    /// @brief Constructs an instance bound to a driver.
    /// @param[in] driver Reference to the owning XdpDriver.
    explicit XdpInstance(XdpDriver& driver);

    /// @brief Destroys the instance and releases resources.
    ~XdpInstance() noexcept;

    /// @brief Copy construction is deleted.
    XdpInstance(const XdpInstance&) = delete;

    /// @brief Copy assignment is deleted.
    XdpInstance& operator=(const XdpInstance&) = delete;

    /// @brief Prepares the instance: resolves ifindex, remembers queue.
    /// @param[in] iface Network interface name.
    /// @param[in] queueId Queue ID.
    /// @return true on success, false otherwise.
    bool create(const std::string& iface, uint32_t queueId);

    /// @brief Binds the AF_XDP socket to the shared UMEM.
    /// @param[in] umem Pointer to the shared UMEM.
    /// @param[in] cfg Socket configuration.
    /// @return true on success, false otherwise.
    bool bindTo(struct xsk_umem* umem, const struct xsk_socket_config& cfg);

    /// @brief Destroys the instance and releases associated resources.
    void destroy() noexcept;

    /// @brief Returns the socket file descriptor.
    /// @return File descriptor, or -1 if not bound.
    int fd() const noexcept
    {
        return fd_;
    }

    /// @brief Returns the interface name.
    /// @return Const reference to the interface name.
    const std::string& name() const noexcept
    {
        return name_;
    }

    /// @brief Returns the queue ID.
    /// @return Queue ID.
    uint32_t queueId() const noexcept
    {
        return queueId_;
    }

    /// @brief Returns the interface index.
    /// @return Interface index.
    uint32_t ifindex() const noexcept
    {
        return ifindex_;
    }

    /// @brief Checks whether the instance is active.
    /// @return true if active, false otherwise.
    bool active() const noexcept
    {
        return active_;
    }

    /// @brief Sets the active flag.
    /// @param[in] v New active state.
    void setActive(bool v) noexcept
    {
        active_ = v;
    }

    /// @brief Returns the RX ring consumer.
    /// @return Pointer to the RX ring consumer.
    struct xsk_ring_cons* rxRing() noexcept
    {
        return &rx_;
    }

    /// @brief Returns the TX ring producer.
    /// @return Pointer to the TX ring producer.
    struct xsk_ring_prod* txRing() noexcept
    {
        return &tx_;
    }

    /// @brief Returns the FQ ring producer.
    /// @return Pointer to the FQ ring producer.
    struct xsk_ring_prod* fqRing() noexcept
    {
        return &fq_;
    }

    /// @brief Returns the CQ ring consumer.
    /// @return Pointer to the CQ ring consumer.
    struct xsk_ring_cons* cqRing() noexcept
    {
        return &cq_;
    }

    /// @brief Peer instance for in-kernel-ish forwarding (Pass verdict).
    XdpInstance* peer{nullptr};

private:
    XdpDriver& driver_;               ///< Reference to the owning driver.
    std::string name_;                ///< Interface name.
    uint32_t queueId_{0};             ///< Queue ID.
    uint32_t ifindex_{0};             ///< Interface index.
    int fd_{-1};                      ///< Socket file descriptor.
    bool active_{false};              ///< Active flag.
    struct xsk_socket* xsk_{nullptr}; ///< AF_XDP socket handle.
    struct xsk_ring_cons rx_{};       ///< RX ring consumer.
    struct xsk_ring_prod tx_{};       ///< TX ring producer.
    struct xsk_ring_prod fq_{};       ///< FQ ring producer.
    struct xsk_ring_cons cq_{};       ///< CQ ring consumer.
};

} // namespace snet::driver