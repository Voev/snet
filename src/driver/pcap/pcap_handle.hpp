#pragma once
#include <cstddef>
#include "forward_types.hpp"
#include <casket/utils/noncopyable.hpp>

namespace snet::driver
{

/// @brief A wrapper class for libpcap packet capture descriptor.
class PcapHandle : public casket::NonCopyable
{
public:
    /// @brief Creates an empty handle.
    constexpr PcapHandle() noexcept = default;

    /// @brief Creates a handle from the provided pcap descriptor.
    /// @param[in] pcapDescriptor The pcap descriptor.
    explicit PcapHandle(PcapType* descriptor) noexcept
        : descriptor_(descriptor)
    {
    }

    /// @brief Move-constructor for pcap descriptor-wrapper.
    /// @param[in] other R-value reference.
    PcapHandle(PcapHandle&& other) noexcept
        : descriptor_(other.descriptor_)
    {
        other.descriptor_ = nullptr;
    }

    /// @brief Move-assignment operator for pcap descriptor-wrapper.
    /// @param[in] other R-value reference.
    /// @return L-value reference of descriptor-wrapper.
    PcapHandle& operator=(PcapHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.descriptor_);
            other.descriptor_ = nullptr;
        }
        return *this;
    }

    PcapHandle& operator=(std::nullptr_t) noexcept
    {
        reset();
        return *this;
    }

    /// @brief Destructor of descriptor-wrapper.
    ~PcapHandle()
    {
        reset();
    }

    /// @brief Checks for valid state of descriptor.
    /// @retval true - if the handle is not null.
    /// @retval false - otherwise.
    bool isValid() const noexcept
    {
        return descriptor_ != nullptr;
    }

    /// @brief Provdes access to descriptor.
    /// @return The pcap descriptor.
    PcapType* get() const noexcept
    {
        return descriptor_;
    }

    /// @brief Releases ownership of the handle and returns the pcap descriptor.
    /// @return The pcap descriptor or nullptr if no handle is owned.
    PcapType* release() noexcept
    {
        auto result = descriptor_;
        descriptor_ = nullptr;
        return result;
    }

    /// @brief Replaces the managed handle with the provided one.
    /// @param descriptor A new pcap descriptor to manage.
    /// @remarks If the handle contains a non-null descriptor it will be closed.
    void reset(PcapType* descriptor = nullptr) noexcept;

    /// @brief Helper function to retrieve the last error string for pcap descriptor.
    /// @return A null-terminated view of the last error string.
    const char* getLastError() const noexcept;

    /// @return True if the handle is not null, false otherwise.
    explicit operator bool() const noexcept
    {
        return isValid();
    }

    operator PcapType*() const
    {
        return this->get();
    }

    bool operator==(std::nullptr_t) const noexcept
    {
        return !isValid();
    }

    bool operator!=(std::nullptr_t) const noexcept
    {
        return isValid();
    }

private:
    PcapType* descriptor_{nullptr};
};

} // namespace snet::driver