#pragma once

#include <cstdint>
#include <variant>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls {

/// One `KeyShareEntry` from RFC 8446 §4.2.8:
///   `<group: uint16> <key_exchange: opaque<1..2^16-1>>`
class KeyShareEntry final {
public:
    KeyShareEntry() noexcept = default;

    /// @brief Constructs an empty entry for @p group.
    /// @param[in] group The named group.
    explicit KeyShareEntry(crypto::GroupParams group) noexcept
        : groupParams_(group) {}

    void setGroup(crypto::GroupParams group) noexcept { groupParams_ = group; }
    crypto::GroupParams getGroup() const noexcept { return groupParams_; }

    /// @brief Fills `key_exchange_` from a key object.
    /// @param[in] key Public key to encode.
    /// @throws casket::RuntimeError if the group is not a supported ECDH group.
    /// @note Not part of the `ExtensionLike` contract: uses crypto, may throw.
    void setPublicKey(const Key* key);

    /// @brief Reconstructs a key object from `key_exchange_`.
    /// @return Public key, or nullptr on unsupported group.
    /// @note Not part of the `ExtensionLike` contract: uses crypto.
    crypto::KeyPtr getPublicKey() const;

    /// @brief Checks whether the entry is default-constructed.
    /// @retval true  Group is `NONE` and body is empty.
    /// @retval false Otherwise.
    bool empty() const noexcept {
        return (groupParams_ == crypto::GroupParams::NONE) && keyExchange_.empty();
    }

    /// @brief Parses one entry from @p reader.
    /// @param[in,out] reader Reader positioned at the entry.
    /// @return DecodeError::None on success, error otherwise.
    utils::DecodeError deserialize(utils::DataReader& reader) noexcept {
        groupParams_ = static_cast<crypto::GroupParams>(reader.get_uint16_t());
        if (!reader.ok()) return reader.take_error();
        reader.get_tls_length_value_into(2, keyExchange_);
        return reader.take_error();
    }

    /// @brief Serializes one entry into @p output.
    /// @param[in] output Destination buffer; must hold 4 + keyExchange_.size() bytes.
    /// @return Bytes written on success, kSerializationFailed if @p output is too small.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept {
        const std::size_t n = keyExchange_.size();
        if (n > 0xFFFF) return 0;
        if (output.size_bytes() < 4 + n) return 0;

        const auto code = groupParams_.wireCode();
        output[0] = static_cast<std::uint8_t>(code >> 8);
        output[1] = static_cast<std::uint8_t>(code);
        output[2] = static_cast<std::uint8_t>(n >> 8);
        output[3] = static_cast<std::uint8_t>(n);
        if (n) std::memcpy(output.data() + 4, keyExchange_.data(), n);
        return 4 + n;
    }

    /// @brief Gets the raw `key_exchange` bytes.
    nonstd::span<const std::uint8_t> keyExchange() const noexcept {
        return {keyExchange_.data(), keyExchange_.size()};
    }

private:
    std::vector<std::uint8_t> keyExchange_;   ///< Raw public key bytes.
    crypto::GroupParams       groupParams_{}; ///< Named group of this entry.
};

// ---------------------------------------------------------------------------
// ClientHello form: <2-byte length> <KeyShareEntry>*
// ---------------------------------------------------------------------------

class KeyShareClientHello final {
public:
    KeyShareClientHello() noexcept = default;

    /// @brief Builds one entry per supported group (client side).
    /// @param[in] supported Supported groups; order is preserved.
    explicit KeyShareClientHello(const std::vector<crypto::GroupParams>& supported);

    /// @brief Replaces all entries with a single entry for @p toOffer.
    void retryOffer(crypto::GroupParams toOffer);

    /// @brief Collects all offered groups into @p out (clears it first).
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief ClientHello never selects a group.
    /// @throws std::logic_error Always.
    crypto::GroupParams selectedGroup() const;

    void setPublicKey(std::size_t idx, const Key* key);
    crypto::KeyPtr getPublicKey(std::size_t idx) const;

    /// @brief Always `false` -- RFC 8446 allows an empty client_shares.
    bool empty() const noexcept { return false; }

    /// @brief Parses the ClientHello form from @p input.
    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the ClientHello form into @p output.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;

private:
    std::vector<KeyShareEntry> clientKeyShares_;   ///< Offered entries; groups unique.
};

// ---------------------------------------------------------------------------
// ServerHello form: <KeyShareEntry>  (exactly one, no length prefix)
// ---------------------------------------------------------------------------

class KeyShareServerHello final {
public:
    KeyShareServerHello() noexcept = default;

    KeyShareServerHello(crypto::GroupParams group, const Key* serverKey);

    void setPublicKey(const Key* key);
    crypto::KeyPtr getPublicKey(std::size_t) const;

    /// @brief Collects the single selected group into @p out.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    crypto::GroupParams selectedGroup() const noexcept { return serverKeyShare_.getGroup(); }

    bool empty() const noexcept { return serverKeyShare_.empty(); }

    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept {
        return serverKeyShare_.serialize(output);
    }

private:
    KeyShareEntry serverKeyShare_;   ///< Single selected entry.
};

// ---------------------------------------------------------------------------
// HelloRetryRequest form: <selected_group: uint16>  (exactly 2 bytes)
// ---------------------------------------------------------------------------

class KeyShareHelloRetryRequest final {
public:
    KeyShareHelloRetryRequest() noexcept = default;

    explicit KeyShareHelloRetryRequest(crypto::GroupParams selectedGroup) noexcept
        : selectedGroup_(selectedGroup) {}

    crypto::GroupParams selectedGroup() const noexcept { return selectedGroup_; }

    /// @brief HRR never offers groups.
    /// @throws std::logic_error Always.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    bool empty() const noexcept { return selectedGroup_ == crypto::GroupParams::NONE; }

    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept {
        if (output.size_bytes() < 2) return 0;
        const auto code = selectedGroup_.wireCode();
        output[0] = static_cast<std::uint8_t>(code >> 8);
        output[1] = static_cast<std::uint8_t>(code);
        return 2;
    }

private:
    crypto::GroupParams selectedGroup_{crypto::GroupParams::NONE};   ///< Selected group.
};

// ---------------------------------------------------------------------------
// KeyShare extension: variant of the three forms.
// ---------------------------------------------------------------------------

/// KeyShare Extension (RFC 8446 §4.2.8).
///
/// The wire format depends on the carrying handshake message:
///   * ClientHello:        `<2-byte length> <KeyShareEntry>*`
///   * ServerHello:        `<KeyShareEntry>` (exactly one)
///   * HelloRetryRequest:  `<selected_group: uint16>` (exactly 2 bytes)
///
/// `deserialize` requires the `HandshakeType` to pick the right form; this
/// is the only extension in the set that needs the handshake type.
class KeyShare final {
public:
    using Variant = std::variant<
        KeyShareClientHello,
        KeyShareServerHello,
        KeyShareHelloRetryRequest>;

    // ---- ExtensionLike contract ----
    static constexpr ExtensionCode staticType() noexcept {
        return ExtensionCode::KeyShare;
    }

    KeyShare() noexcept = default;

    /// @brief Constructs the ClientHello form from supported groups.
    explicit KeyShare(const std::vector<crypto::GroupParams>& supported)
        : keyShare_(KeyShareClientHello(supported)) {}

    /// @brief Constructs the ServerHello form from a selected group and key.
    KeyShare(crypto::GroupParams selectedGroup, const Key* serverKey);

    /// @brief Constructs the HelloRetryRequest form.
    explicit KeyShare(crypto::GroupParams selectedGroup) noexcept
        : keyShare_(KeyShareHelloRetryRequest(selectedGroup)) {}

    /// @brief Checks whether the active form is empty.
    bool empty() const noexcept {
        return std::visit([](const auto& inner) noexcept { return inner.empty(); }, keyShare_);
    }

    /// @brief Serializes the active form into @p output.
    /// @param[in] whoami Side (Client or Server); unused.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, kSerializationFailed otherwise.
    std::size_t serialize(Side /*whoami*/, nonstd::span<uint8_t> output) const noexcept {
        return std::visit([output](const auto& inner) noexcept {
            return inner.serialize(output);
        }, keyShare_);
    }

    // ---- parse (the only extension that needs the handshake type) ----

    /// @brief Parses the extension body for a given handshake message type.
    /// @param[in] side           Side (Client or Server); unused.
    /// @param[in] input          Wire bytes of the extension_data field.
    /// @param[in] handshakeType  One of ClientHello, ServerHello, HelloRetryRequest.
    /// @return DecodeError::None on success; error otherwise.
    utils::DecodeError deserialize(Side /*side*/,
                                   nonstd::span<const uint8_t> input,
                                   HandshakeType handshakeType) noexcept;

    // ---- form-specific operations (may throw) ----

    /// @brief Selects the active form's public key and sets it (ServerHello only).
    void setPublicKey(const Key* key);
    /// @brief Selects the active form's public key by index (ClientHello only).
    void setPublicKey(std::size_t idx, const Key* key);
    /// @brief Reconstructs a public key (ClientHello / ServerHello only).
    crypto::KeyPtr getPublicKey(std::size_t i = 0) const;

    /// @brief Collects the offered groups of the active form.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief Gets the selected group (ServerHello / HRR only).
    /// @throws std::logic_error for ClientHello.
    crypto::GroupParams selectedGroup() const;

    /// @brief Retries the ClientHello offer against an HRR.
    void retryOffer(const KeyShare& retryRequestKeyShare,
                    const std::vector<crypto::GroupParams>& supportedGroups);

    /// @brief Raw variant access (advanced / tests).
    const Variant& raw() const noexcept { return keyShare_; }

private:
    Variant keyShare_;   ///< Active form.
};

} // namespace snet::tls