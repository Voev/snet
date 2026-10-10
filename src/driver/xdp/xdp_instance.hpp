#pragma once

#include <string>
#include <cstdint>

#include <snet/layers/l2/mac_address.hpp>

#include <xdp/xsk.h>
#include <bpf/libbpf.h>

namespace snet::driver
{

/// UMEM and fill/completion ring state shared between kernel and userspace.
/// A single UMEM is shared across all interfaces so frames can be forwarded
/// between interfaces without copying.
struct XdpUmemInfo
{
    void* buffer{nullptr};
    struct xsk_ring_prod fill{};
    struct xsk_ring_cons comp{};
    struct xsk_umem* umem{nullptr};
    uint64_t frameSize{0};
    uint32_t numFrames{0};
};

/// Per-socket AF_XDP state (RX/TX rings).
struct XdpSocketInfo
{
    struct xsk_ring_cons rx{};
    struct xsk_ring_prod tx{};
    struct xsk_socket* xsk{nullptr};

    /// fd of the XSK socket, also stored here for convenience.
    int xskFd{-1};
};

/// Describes a single network interface bound to the driver.
/// Each interface has its own AF_XDP socket, XSK map and XDP program,
/// but shares the driver's UMEM with all other interfaces.
struct XdpInstance
{
    std::string name;
    uint32_t ifindex{0};
    uint32_t ip{0};
    uint32_t netmask{0};
    layers::MacAddress mac;

    /// Index of the peer interface in the driver's instance vector.
    /// Using an index (rather than a raw pointer) keeps peer references
    /// stable even if the vector is reallocated.
    size_t peerIdx{static_cast<size_t>(-1)};

    XdpSocketInfo socket;

    /// fd of the BPF_MAP_TYPE_XSKMAP used by the XDP program attached
    /// to this interface.
    int xskMapFd{-1};

    /// fd of the loaded XDP program attached to this interface.
    int xdpProgFd{-1};

    /// Owning BPF object, closed on cleanup.
    struct bpf_object* bpfObj{nullptr};

    bool hasIp() const noexcept { return ip != 0 && netmask != 0; }
};

} // namespace snet::driver