// snet/driver/packet_wrapper.hpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <snet/layers/packet.hpp>
#include <casket/utils/container_of.hpp>

namespace snet::layers
{

/// @brief Base template for packet wrappers with intrusive list support.
/// @tparam Derived The derived wrapper type (CRTP pattern).
template <typename Derived>
struct PacketWrapper
{
    /// Packet viewer (non-owning).
    layers::Packet packet;

    /// @brief Gets the parent wrapper from an embedded Packet pointer.
    /// @param packet Pointer to the embedded Packet.
    /// @return Pointer to the parent wrapper, or nullptr if input is null.
    static Derived* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;

        auto* wrapper = casket::container_of(packet, &PacketWrapper<Derived>::packet);

        return static_cast<Derived*>(wrapper);
    }

    /// @brief Const version of fromPacket.
    /// @param packet Const pointer to the embedded Packet.
    /// @return Const pointer to the parent wrapper, or nullptr if input is null.
    static const Derived* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;

        auto* wrapper = casket::container_of(const_cast<layers::Packet*>(packet), &PacketWrapper<Derived>::packet);

        return static_cast<const Derived*>(wrapper);
    }

    /// @brief Returns the embedded Packet as a pointer.
    layers::Packet* asPacket() noexcept
    {
        return &packet;
    }

    /// @brief Returns the embedded Packet as a const pointer.
    const layers::Packet* asPacket() const noexcept
    {
        return &packet;
    }

    /// @brief Resets the packet for reuse.
    /// Derived classes should override this method to reset their own state.
    /// Always call the base implementation first.
    virtual void reset() noexcept
    {
        packet.clear();
        packet.setTimestamp(layers::Timestamp());
    }

    /// @brief Virtual destructor for proper cleanup.
    virtual ~PacketWrapper() = default;

    PacketWrapper(PacketWrapper&&) = default;
    PacketWrapper& operator=(PacketWrapper&&) = default;

    PacketWrapper(const PacketWrapper&) = delete;
    PacketWrapper& operator=(const PacketWrapper&) = delete;

protected:
    PacketWrapper() = default;
};

} // namespace snet::layers