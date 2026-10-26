#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/exts/extension_mask.hpp>
#include <snet/tls/exts/extension_variant.hpp>

namespace snet::tls
{

/// @brief A block of TLS extensions in a hello message.
///
/// Storage is a flat `std::vector<ExtensionVariant>`; `UnknownExtension` is
/// itself a variant alternative, so the order of extensions on the wire is
/// preserved exactly. Dispatch is via `std::visit` → static `switch`: no
/// virtual calls, no RTTI, no `dynamic_cast`, no `unique_ptr`.
///
/// All parsing and serialization is `noexcept`; errors are reported through
/// `utils::DecodeError`.
class Extensions final
{
public:
    /// @brief Default constructor.
    Extensions() = default;

    /// @brief Default destructor.
    ~Extensions() = default;

    /// @brief Move constructor.
    Extensions(Extensions&&) noexcept = default;

    /// @brief Move assignment operator.
    Extensions& operator=(Extensions&&) noexcept = default;

    Extensions(const Extensions&) = delete;
    Extensions& operator=(const Extensions&) = delete;

    /// @brief Parses extensions from a hello body.
    /// @param[in] side          Side (Client or Server).
    /// @param[in] input         Wire bytes of the `extensions` field.
    /// @param[in] handshakeType Carrying message type; used by `KeyShare`.
    /// @return DecodeError::None on success. On error the container is reset
    ///         to empty (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input, HandshakeType handshakeType) noexcept;

    /// @brief Serializes extensions into @p buffer (with 2-byte total length).
    /// @param[in] whoami Side (Client or Server).
    /// @param[in] buffer Destination buffer.
    /// @return Bytes written on success, 0 if @p buffer is too small or any
    ///         extension's serialization failed.
    std::size_t serialize(Side whoami, nonstd::span<uint8_t> buffer) const noexcept;

    /// @brief Gets an extension by type.
    /// @tparam T Concrete extension type (must be an alternative of `ExtensionVariant`).
    /// @return Pointer into the stored variant, or nullptr if absent.
    template <typename T>
    T* get() noexcept
    {
        const auto idx = find(T::staticType());
        return idx == npos ? nullptr : std::get_if<T>(&extensions_[idx]);
    }

    /// @brief Gets an extension by type (const overload).
    /// @tparam T Concrete extension type (must be an alternative of `ExtensionVariant`).
    /// @return Pointer into the stored variant, or nullptr if absent.
    template <typename T>
    const T* get() const noexcept
    {
        const auto idx = find(T::staticType());
        return idx == npos ? nullptr : std::get_if<T>(&extensions_[idx]);
    }

    /// @brief Checks whether an extension of type @p T is present.
    /// @tparam T Concrete extension type.
    /// @retval true  Present.
    /// @retval false Absent.
    template <typename T>
    bool has() const noexcept
    {
        return has(T::staticType());
    }

    /// @brief Checks whether an extension with @p type is present.
    /// @param[in] type Extension code.
    /// @retval true  Present.
    /// @retval false Absent.
    bool has(ExtensionCode type) const noexcept
    {
        return find(type) != npos;
    }

    /// @brief Gets a raw variant pointer by code.
    /// @param[in] type Extension code.
    /// @return Pointer into the stored variant, or nullptr if absent.
    ExtensionVariant* get(ExtensionCode type) noexcept
    {
        const auto idx = find(type);
        return idx == npos ? nullptr : &extensions_[idx];
    }

    /// @brief Gets a raw variant pointer by code (const overload).
    /// @param[in] type Extension code.
    /// @return Pointer into the stored variant, or nullptr if absent.
    const ExtensionVariant* get(ExtensionCode type) const noexcept
    {
        const auto idx = find(type);
        return idx == npos ? nullptr : &extensions_[idx];
    }

    /// @brief Gets the number of extensions.
    /// @return Extension count.
    std::size_t size() const noexcept
    {
        return extensions_.size();
    }

    /// @brief Checks whether there are no extensions at all.
    /// @retval true  Container is empty.
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return extensions_.empty();
    }

    /// @brief Gets all extensions in wire order.
    /// @return Const reference to the flat variant vector.
    const std::vector<ExtensionVariant>& all() const noexcept
    {
        return extensions_;
    }

    /// @brief Adds an extension.
    /// @param[in] ext Extension to add; moved into the container.
    /// @return false if a duplicate code is already present or on allocation
    ///         failure; true on success.
    bool add(ExtensionVariant ext) noexcept;

    /// @brief Removes and returns an extension by code.
    /// @param[in] type Extension code.
    /// @return Extension on success; `std::nullopt` if absent.
    std::optional<ExtensionVariant> take(ExtensionCode type);

    /// @brief Removes and returns an extension by type.
    /// @tparam T Concrete extension type.
    /// @return Extension on success; `std::nullopt` if absent or type mismatch.
    /// @note On type mismatch the extension is put back into the container.
    template <typename T>
    std::optional<T> take()
    {
        auto v = take(T::staticType());
        if (!v)
            return std::nullopt;
        if (auto* p = std::get_if<T>(&*v))
        {
            T out = std::move(*p);
            return out;
        }
        (void)add(std::move(*v));
        return std::nullopt;
    }

    /// @brief Removes an extension by code.
    /// @param[in] type Extension code.
    /// @retval true  Removed.
    /// @retval false Not present.
    bool removeExtension(ExtensionCode type)
    {
        return take(type).has_value();
    }

    /// @brief Gets a sorted set of all present extension codes.
    /// @return Sorted set of codes (public API; not for hot path).
    std::set<ExtensionCode> extensionTypes() const;

    /// @brief Checks whether any extension other than @p allowed is present.
    /// @param[in] allowed                Allowed extension codes.
    /// @param[in] allowUnknownExtensions If true, unknown codes are tolerated.
    /// @retval true  At least one disallowed extension is present.
    /// @retval false All present extensions are in @p allowed (or unknown and
    ///               tolerated).
    bool containsOtherThan(const std::set<ExtensionCode>& allowed, bool allowUnknownExtensions = false) const;

    /// @brief Like `containsOtherThan(allowed, true)`.
    /// @param[in] allowed Allowed extension codes.
    /// @return Value of `containsOtherThan(allowed, true)`.
    bool containsImplementedExtensionsOtherThan(const std::set<ExtensionCode>& allowed) const
    {
        return containsOtherThan(allowed, true);
    }

private:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

    /// @brief Finds an extension by code.
    /// @param[in] type Extension code.
    /// @return Index into `extensions_`, or `npos` if absent.
    std::size_t find(ExtensionCode type) const noexcept
    {
        for (std::size_t i = 0; i < extensions_.size(); ++i)
        {
            if (extensionType(extensions_[i]) == type)
                return i;
        }
        return npos;
    }

    /// @brief Clears the container and the mask.
    void clearAll() noexcept;

    /// @brief Rebuilds `mask_` from `extensions_`.
    void rebuildMask() noexcept;

    std::vector<ExtensionVariant> extensions_; ///< Extensions, insertion order.
    ExtensionMask mask_;                       ///< Fast `has(known code)`.
};

} // namespace snet::tls