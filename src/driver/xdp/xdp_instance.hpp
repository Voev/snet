#pragma once

#include <cstdint>
#include <string>

#include <xdp/xsk.h>

namespace snet::driver
{

class XdpDriver;

/// @brief Per-queue AF_XDP endpoint.
///
/// One instance == one (iface, queueId) pair == one AF_XDP socket registered
/// in the BPF program's XSKMAP under key = queueId.
class XdpInstance final
{
public:
    explicit XdpInstance(XdpDriver& driver);
    ~XdpInstance() noexcept;

    XdpInstance(const XdpInstance&) = delete;
    XdpInstance& operator=(const XdpInstance&) = delete;

    /// @brief Prepare the instance: resolve ifindex, remember queue.
    bool create(const std::string& iface, uint32_t queueId);

    /// @brief Bind AF_XDP socket to the shared UMEM.
    bool bindTo(struct xsk_umem* umem, const struct xsk_socket_config& cfg);

    void destroy() noexcept;

    int fd() const noexcept
    {
        return fd_;
    }
    const std::string& name() const noexcept
    {
        return name_;
    }
    uint32_t queueId() const noexcept
    {
        return queueId_;
    }
    uint32_t ifindex() const noexcept
    {
        return ifindex_;
    }
    bool active() const noexcept
    {
        return active_;
    }
    void setActive(bool v) noexcept
    {
        active_ = v;
    }

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

    /// @brief Peer instance for in-kernel-ish forwarding (Pass verdict).
    XdpInstance* peer{nullptr};

private:
    XdpDriver& driver_;
    std::string name_;
    uint32_t queueId_{0};
    uint32_t ifindex_{0};
    int fd_{-1};
    bool active_{false};

    struct xsk_socket* xsk_{nullptr};
    struct xsk_ring_cons rx_{};
    struct xsk_ring_prod tx_{};
    struct xsk_ring_prod fq_{};
    struct xsk_ring_cons cq_{};
};

} // namespace snet::driver