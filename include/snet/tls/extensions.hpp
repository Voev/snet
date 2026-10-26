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
#include <snet/tls/exts/unknown_extension.hpp>

namespace snet::tls {

/// A block of TLS extensions in a hello message.
///
/// Storage is a flat `std::vector<ExtensionVariant>` plus a parallel
/// `std::vector<UnknownExtension>` for codes that are not represented in the
/// variant. Dispatch is via `std::visit` → static `switch`: no virtual calls,
/// no RTTI, no `dynamic_cast`, no `unique_ptr`.
///
/// All parsing and serialization is `noexcept`; errors are reported through
/// `utils::DecodeError`.
class Extensions final {
public:
    // ---- lifetime ---------------------------------------------------------

    Extensions() = default;
    ~Extensions() = default;

    Extensions(Extensions&&) noexcept = default;
    Extensions& operator=(Extensions&&) noexcept = default;

    Extensions(const Extensions&) = delete;
    Extensions& operator=(const Extensions&) = delete;

    // ---- parse / serialize ------------------------------------------------

    /// @brief Parses extensions from a hello body.
    /// @param[in] side          Side (Client or Server).
    /// @param[in] input         Wire bytes of the `extensions` field.
    /// @param[in] handshakeType Carrying message type; used by `KeyShare`.
    /// @return DecodeError::None on success. On error the container is reset
    ///         to empty (strong guarantee).
    utils::DecodeError deserialize(Side side,
                                   nonstd::span<const uint8_t> input,
                                   HandshakeType handshakeType) noexcept;

    /// @brief Serializes extensions into @p buffer (with 2-byte total length).
    /// @param[in] whoami Side (Client or Server).
    /// @param[in] buffer Destination buffer.
    /// @return Bytes written on success, 0 if @p buffer is too small or any
    ///         extension's serialization failed.
    std::size_t serialize(Side whoami, nonstd::span<uint8_t> buffer) const noexcept;

    // ---- typed accessors --------------------------------------------------

    /// @brief Gets an extension by type.
    /// @tparam T Concrete extension type (must be an alternative of `ExtensionVariant`).
    /// @return Pointer into the stored variant, or nullptr if absent.
    template <typename T>
    T* get() noexcept {
        const auto idx = find(T::staticType());
        return idx == npos ? nullptr : std::get_if<T>(&extensions_[idx]);
    }

    /// @brief Gets an extension by type (const overload).
    template <typename T>
    const T* get() const noexcept {
        const auto idx = find(T::staticType());
        return idx == npos ? nullptr : std::get_if<T>(&extensions_[idx]);
    }

    /// @brief Checks whether an extension of type @p T is present.
    template <typename T>
    bool has() const noexcept {
        return has(T::staticType());
    }

    /// @brief Checks whether an extension with @p type is present.
    bool has(ExtensionCode type) const noexcept {
        return mask_.contains(type) || findUnknown(type) != npos;
    }

    /// @brief Raw variant pointer by code (nullptr if absent).
    ExtensionVariant* get(ExtensionCode type) noexcept {
        const auto idx = find(type);
        return idx == npos ? nullptr : &extensions_[idx];
    }

    /// @brief Raw variant pointer by code (const overload).
    const ExtensionVariant* get(ExtensionCode type) const noexcept {
        const auto idx = find(type);
        return idx == npos ? nullptr : &extensions_[idx];
    }

    // ---- container views --------------------------------------------------

    std::size_t size() const noexcept { return extensions_.size() + unknown_.size(); }
    bool empty() const noexcept { return extensions_.empty() && unknown_.empty(); }

    /// @brief All known extensions, in insertion order.
    const std::vector<ExtensionVariant>& all() const noexcept { return extensions_; }

    /// @brief All unknown extensions, in insertion order.
    const std::vector<UnknownExtension>& unknown() const noexcept { return unknown_; }

    // ---- mutation ---------------------------------------------------------

    /// @brief Adds a known extension.
    /// @return false if a duplicate code is already present or on allocation failure.
    bool add(ExtensionVariant ext) noexcept;

    /// @brief Adds an unknown extension.
    /// @return false if a duplicate code is already present or on allocation failure.
    bool addUnknown(UnknownExtension ext) noexcept;

    /// @brief Removes and returns a known extension by code.
    std::optional<ExtensionVariant> take(ExtensionCode type);

    /// @brief Removes and returns a known extension by type.
    template <typename T>
    std::optional<T> take() {
        auto v = take(T::staticType());
        if (!v) return std::nullopt;
        if (auto* p = std::get_if<T>(&*v)) {
            T out = std::move(*p);
            return out;
        }
        // Type mismatch -- put it back, report failure.
        (void)add(std::move(*v));
        return std::nullopt;
    }

    /// @brief Removes and returns an unknown extension by code.
    std::optional<UnknownExtension> takeUnknown(ExtensionCode type);

    /// @brief Removes an extension (known or unknown) by code.
    bool removeExtension(ExtensionCode type) {
        if (take(type).has_value()) return true;
        return takeUnknown(type).has_value();
    }

    // ---- policy checks ----------------------------------------------------

    /// @brief Sorted set of all present extension codes (public API).
    std::set<ExtensionCode> extensionTypes() const;

    /// @brief Checks whether any extension other than @p allowed is present.
    /// @param[in] allowed              Allowed extension codes.
    /// @param[in] allowUnknownExtensions If true, unknown codes are tolerated.
    bool containsOtherThan(const std::set<ExtensionCode>& allowed,
                           bool allowUnknownExtensions = false) const;

    /// @brief Like `containsOtherThan(allowed, true)`.
    bool containsImplementedExtensionsOtherThan(const std::set<ExtensionCode>& allowed) const {
        return containsOtherThan(allowed, true);
    }

private:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

    /// @brief Finds a known extension by code; returns `npos` if absent.
    std::size_t find(ExtensionCode type) const noexcept {
        if (!mask_.contains(type)) return npos;
        for (std::size_t i = 0; i < extensions_.size(); ++i) {
            if (extensionType(extensions_[i]) == type) return i;
        }
        return npos;
    }

    /// @brief Finds an unknown extension by code; returns `npos` if absent.
    std::size_t findUnknown(ExtensionCode type) const noexcept {
        for (std::size_t i = 0; i < unknown_.size(); ++i) {
            if (unknown_[i].type() == type) return i;
        }
        return npos;
    }

    void clearAll() noexcept;
    void rebuildMask() noexcept;

    std::vector<ExtensionVariant> extensions_;   ///< Known extensions, insertion order.
    std::vector<UnknownExtension> unknown_;      ///< Unknown codes, raw bytes.
    ExtensionMask                 mask_;         ///< Fast `has(known code)`.
};

} // namespace snet::tls