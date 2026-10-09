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

/// Per-socket AF_XDP state (RX/TX rings and batching hints).
struct XdpSocketInfo
{
    struct xsk_ring_cons rx{};
    struct xsk_ring_prod tx{};
    struct xsk_socket* xsk{nullptr};
    uint32_t outstandingTx{0};
    uint32_t rxBatchSize{64};
    uint32_t txBatchSize{64};
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

    /// Paired interface for transparent bridge forwarding.
    XdpInstance* peer{nullptr};

    XdpSocketInfo socket;

    /// fd of the XSK socket, used as the value in the XSK map.
    int xskFd{-1};

    /// fd of the BPF_MAP_TYPE_XSKMAP used by the XDP program.
    int xskMapFd{-1};

    /// fd of the loaded XDP program.
    int xdpProgFd{-1};

    /// Owning BPF object, closed on cleanup.
    struct bpf_object* bpfObj{nullptr};
};

} // namespace snet::driver