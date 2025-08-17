/// @file
/// @brief Declaration of the TLS extensions.

#pragma once

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/utils/data_reader.hpp>

#include <snet/tls/exts/alpn.hpp>
#include <snet/tls/exts/certificate_type.hpp>
#include <snet/tls/exts/encrypt_then_mac.hpp>
#include <snet/tls/exts/extended_master_secret.hpp>
#include <snet/tls/exts/record_size_limit.hpp>
#include <snet/tls/exts/reneg_extension.hpp>
#include <snet/tls/exts/server_name_indication.hpp>
#include <snet/tls/exts/supported_versions.hpp>
#include <snet/tls/exts/key_share.hpp>
#include <snet/tls/exts/unknown_extension.hpp>

namespace snet::tls {

/// @brief Represents a block of extensions in a hello message.
class Extensions final {
public:
    /// @brief Gets the types of extensions.
    /// @return A set of extension codes.
    std::set<ExtensionCode> extensionTypes() const;

    /// @brief Gets all extensions.
    /// @return A vector of unique pointers to extensions.
    const std::vector<std::unique_ptr<Extension>>& all() const {
        return extensions_;
    }

    /// @brief Gets an extension of a specific type.
    /// @tparam T The type of the extension.
    /// @return A pointer to the extension if found, otherwise nullptr.
    template <typename T>
    T* get() const {
        return dynamic_cast<T*>(get(T::staticType()));
    }

    /// @brief Checks if an extension of a specific type exists.
    /// @tparam T The type of the extension.
    /// @return True if the extension exists, false otherwise.
    template <typename T>
    bool has() const {
        return get<T>() != nullptr;
    }

    /// @brief Checks if an extension of a specific type exists.
    /// @param type The extension code.
    /// @return True if the extension exists, false otherwise.
    bool has(ExtensionCode type) const {
        return get(type) != nullptr;
    }

    /// @brief Gets the number of extensions.
    /// @return The number of extensions.
    size_t size() const {
        return extensions_.size();
    }

    /// @brief Checks if there are no extensions.
    /// @return True if there are no extensions, false otherwise.
    bool empty() const {
        return extensions_.empty();
    }

    /// @brief Adds an extension.
    /// @param extn The unique pointer to the extension.
    void add(std::unique_ptr<Extension> extn);

    /// @brief Adds an extension.
    /// @param extn The pointer to the extension.
    void add(Extension* extn) {
        add(std::unique_ptr<Extension>(extn));
    }

    /// @brief Gets an extension of a specific type.
    /// @param type The extension code.
    /// @return A pointer to the extension if found, otherwise nullptr.
    Extension* get(ExtensionCode type) const {
        const auto i = std::find_if(
            extensions_.cbegin(), extensions_.cend(), [type](const auto& ext) { return ext->type() == type; });

        return (i != extensions_.end()) ? i->get() : nullptr;
    }

    /// @brief Deserializes extensions from a data reader.
    /// @param reader The data reader.
    /// @param from The side (client or server).
    /// @param messageType The handshake type.
    void deserialize(Side side, nonstd::span<const uint8_t> input, const HandshakeType handshakeType);

    /// @brief Checks if the extensions contain any types other than the allowed ones.
    /// @param allowedExtensions The allowed extension types.
    /// @param allowUnknownExtensions If true, ignores unrecognized extensions.
    /// @return True if there are any extensions not in the allowed set, false otherwise.
    bool containsOtherThan(
        const std::set<ExtensionCode>& allowedExtensions, bool allowUnknownExtensions = false) const;

    /// @brief Checks if the extensions contain any implemented types other than the allowed ones.
    /// @param allowedExtensions The allowed extension types.
    /// @return True if there are any implemented extensions not in the allowed set, false otherwise.
    bool containsImplementedExtensionsOtherThan(const std::set<ExtensionCode>& allowedExtensions) const {
        return containsOtherThan(allowedExtensions, true);
    }

    /// @brief Takes an extension of a specific type out of the extensions list.
    /// @tparam T The type of the extension.
    /// @return A unique pointer to the extension if found, otherwise nullptr.
    template <typename T>
    decltype(auto) take() {
        std::unique_ptr<T> out_ptr;

        auto ext = take(T::staticType());
        if (ext != nullptr) {
            out_ptr.reset(dynamic_cast<T*>(ext.get()));
            ext.release();
        }

        return out_ptr;
    }

    /// @brief Takes an extension of a specific type out of the extensions list.
    /// @param type The extension code.
    /// @return A unique pointer to the extension if found, otherwise nullptr.
    std::unique_ptr<Extension> take(ExtensionCode type);

    /// @brief Removes an extension from the extensions list if it exists.
    /// @param type The extension code.
    /// @return True if the extension existed and was removed, false otherwise.
    bool removeExtension(ExtensionCode type) {
        return take(type) != nullptr;
    }

    /// @brief Default constructor.
    Extensions() = default;

    Extensions(const Extensions&) = delete;
    Extensions& operator=(const Extensions&) = delete;

    /// @brief Move constructor.
    Extensions(Extensions&&) = default;

    /// @brief Move assignment operator.
    Extensions& operator=(Extensions&&) = default;

    /// @brief Constructor with data reader, side, and handshake type.
    /// @param side The side (client or server).
    /// @param reader The data reader.
    Extensions(Side side, nonstd::span<const uint8_t> input, const HandshakeType handshakeType) {
        deserialize(side, input, handshakeType);
    }

    size_t serialize(Side whoami, nonstd::span<uint8_t> buffer) const;

private:
    std::vector<std::unique_ptr<Extension>> extensions_;
};

} // namespace snet::tls