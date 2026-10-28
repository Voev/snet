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
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// @brief One `KeyShareEntry` from RFC 8446 §4.2.8.
///
/// Wire format: `<group: uint16> <key_exchange: opaque<1..2^16-1>>`.
class KeyShareEntry final
{
public:
    /// @brief Default constructor.
    KeyShareEntry() noexcept = default;

    /// @brief Constructs an empty entry for @p group.
    /// @param[in] group The named group.
    explicit KeyShareEntry(crypto::GroupParams group) noexcept
        : groupParams_(group)
    {
    }

    /// @brief Sets the named group.
    /// @param[in] group The named group.
    void setGroup(crypto::GroupParams group) noexcept
    {
        groupParams_ = group;
    }

    /// @brief Gets the named group.
    /// @return The named group.
    crypto::GroupParams getGroup() const noexcept
    {
        return groupParams_;
    }

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
    bool empty() const noexcept
    {
        return (groupParams_ == crypto::GroupParams::NONE) && keyExchange_.empty();
    }

    /// @brief Parses one entry from @p reader.
    /// @param[in,out] reader Reader positioned at the entry.
    /// @return DecodeError::None on success, error otherwise.
    utils::DecodeError deserialize(utils::DataReader& reader) noexcept
    {
        groupParams_ = static_cast<crypto::GroupParams>(reader.get_uint16_t());
        if (!reader.ok())
            return reader.take_error();
        reader.get_tls_length_value_into(2, keyExchange_);
        return reader.take_error();
    }

    /// @brief Serializes one entry into @p output.
    /// @param[in] output Destination buffer; must hold `4 + keyExchange_.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small or the body exceeds 65535 bytes.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept
    {
        const std::size_t n = keyExchange_.size();
        if (n > 0xFFFF)
        {
            return kSerializationFailed;
        }

        if (output.size_bytes() < 4 + n)
        {
            return kSerializationFailed;
        }

        const auto code = groupParams_.wireCode();
        output[0] = casket::get_byte<0>(code);
        output[1] = casket::get_byte<1>(code);

        const auto n16 = static_cast<std::uint16_t>(n);
        output[2] = casket::get_byte<0>(n16);
        output[3] = casket::get_byte<1>(n16);

        if (n)
        {
            std::memcpy(output.data() + 4, keyExchange_.data(), n);
        }
        return 4 + n;
    }

    /// @brief Gets the raw `key_exchange` bytes.
    /// @return View over the owned body.
    nonstd::span<const std::uint8_t> keyExchange() const noexcept
    {
        return {keyExchange_.data(), keyExchange_.size()};
    }

private:
    std::vector<std::uint8_t> keyExchange_; ///< Raw public key bytes.
    crypto::GroupParams groupParams_{};     ///< Named group of this entry.
};

/// @brief ClientHello form of the KeyShare extension: a list of offered entries.
class KeyShareClientHello final
{
public:
    /// @brief Default constructor.
    KeyShareClientHello() noexcept = default;

    /// @brief Builds one entry per supported group (client side).
    /// @param[in] supported Supported groups; order is preserved.
    explicit KeyShareClientHello(const std::vector<crypto::GroupParams>& supported);

    /// @brief Replaces all entries with a single entry for @p toOffer.
    /// @param[in] toOffer Group to offer in the retry.
    void retryOffer(crypto::GroupParams toOffer);

    /// @brief Collects all offered groups into @p out (clears it first).
    /// @param[out] out Destination vector; cleared and filled with offered groups.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief ClientHello never selects a group.
    /// @throws std::logic_error Always.
    crypto::GroupParams selectedGroup() const;

    /// @brief Sets the public key of the entry at @p idx.
    /// @param[in] idx Index in `[0, size())`.
    /// @param[in] key Public key to encode.
    /// @throws std::out_of_range if @p idx is out of range.
    void setPublicKey(std::size_t idx, const Key* key);

    /// @brief Reconstructs the public key of the entry at @p idx.
    /// @param[in] idx Index in `[0, size())`.
    /// @return Public key, or nullptr on unsupported group.
    /// @throws std::out_of_range if @p idx is out of range.
    crypto::KeyPtr getPublicKey(std::size_t idx) const;

    /// @brief Always `false` -- RFC 8446 allows an empty `client_shares`.
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Parses the ClientHello form from @p input.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success; error otherwise.
    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the ClientHello form into @p output.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` otherwise.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;

private:
    std::vector<KeyShareEntry> clientKeyShares_; ///< Offered entries; groups unique.
};

/// @brief ServerHello form of the KeyShare extension: exactly one entry.
class KeyShareServerHello final
{
public:
    /// @brief Default constructor.
    KeyShareServerHello() noexcept = default;

    /// @brief Constructs from a selected group and a server public key.
    /// @param[in] group     Selected named group.
    /// @param[in] serverKey Server public key to encode.
    KeyShareServerHello(crypto::GroupParams group, const Key* serverKey);

    /// @brief Sets the server public key.
    /// @param[in] key Public key to encode.
    void setPublicKey(const Key* key);

    /// @brief Reconstructs the server public key.
    /// @param[in] unused Unused.
    /// @return Public key, or nullptr on unsupported group.
    crypto::KeyPtr getPublicKey(std::size_t) const;

    /// @brief Collects the single selected group into @p out.
    /// @param[out] out Destination vector; cleared and filled with one group.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief Gets the selected group.
    /// @return The selected group.
    crypto::GroupParams selectedGroup() const noexcept
    {
        return serverKeyShare_.getGroup();
    }

    /// @brief Checks whether the entry is default-constructed.
    /// @retval true  No entry.
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return serverKeyShare_.empty();
    }

    /// @brief Parses the ServerHello form from @p input.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success; error otherwise.
    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the ServerHello form into @p output.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` otherwise.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept
    {
        return serverKeyShare_.serialize(output);
    }

private:
    KeyShareEntry serverKeyShare_; ///< Single selected entry.
};

/// @brief HelloRetryRequest form of the KeyShare extension: a single group.
class KeyShareHelloRetryRequest final
{
public:
    /// @brief Default constructor.
    KeyShareHelloRetryRequest() noexcept = default;

    /// @brief Constructs from the selected group.
    /// @param[in] selectedGroup Group the server asks the client to use.
    explicit KeyShareHelloRetryRequest(crypto::GroupParams selectedGroup) noexcept
        : selectedGroup_(selectedGroup)
    {
    }

    /// @brief Gets the selected group.
    /// @return The selected group.
    crypto::GroupParams selectedGroup() const noexcept
    {
        return selectedGroup_;
    }

    /// @brief HRR never offers groups.
    /// @param[out] out Unused.
    /// @throws std::logic_error Always.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief Checks whether the selected group is unset.
    /// @retval true  Group is `NONE`.
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return selectedGroup_ == crypto::GroupParams::NONE;
    }

    /// @brief Parses the HelloRetryRequest form from @p input.
    /// @param[in] input Wire bytes of the extension_data field (exactly 2 bytes).
    /// @return DecodeError::None on success; error otherwise.
    utils::DecodeError deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the HelloRetryRequest form into @p output.
    /// @param[in] output Destination buffer; must hold at least 2 bytes.
    /// @return 2 on success, `kSerializationFailed` if @p output is too small.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept
    {
        if (output.size_bytes() < 2)
        {
            return kSerializationFailed;
        }
        const auto code = selectedGroup_.wireCode();
        output[0] = casket::get_byte<0>(code);
        output[1] = casket::get_byte<1>(code);
        return 2;
    }

private:
    crypto::GroupParams selectedGroup_{crypto::GroupParams::NONE}; ///< Selected group.
};

/// @brief KeyShare Extension (RFC 8446 §4.2.8).
///
/// The wire format depends on the carrying handshake message:
///   * ClientHello:        `<2-byte length> <KeyShareEntry>*`
///   * ServerHello:        `<KeyShareEntry>` (exactly one)
///   * HelloRetryRequest:  `<selected_group: uint16>` (exactly 2 bytes)
///
/// `deserialize` requires the `HandshakeType` to pick the right form; this
/// is the only extension in the set that needs the handshake type.
class KeyShare final
{
public:
    /// @brief Active form.
    using Variant = std::variant<KeyShareClientHello, KeyShareServerHello, KeyShareHelloRetryRequest>;

    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::KeyShare.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::KeyShare;
    }

    /// @brief Default constructor; active form is `KeyShareClientHello`.
    KeyShare() noexcept = default;

    /// @brief Constructs the ClientHello form from supported groups.
    /// @param[in] supported Supported groups; one entry is created per group.
    explicit KeyShare(const std::vector<crypto::GroupParams>& supported)
        : keyShare_(KeyShareClientHello(supported))
    {
    }

    /// @brief Constructs the ServerHello form from a selected group and key.
    /// @param[in] selectedGroup Selected named group.
    /// @param[in] serverKey     Server public key to encode.
    KeyShare(crypto::GroupParams selectedGroup, const Key* serverKey);

    /// @brief Constructs the HelloRetryRequest form.
    /// @param[in] selectedGroup Group the server asks the client to use.
    explicit KeyShare(crypto::GroupParams selectedGroup) noexcept
        : keyShare_(KeyShareHelloRetryRequest(selectedGroup))
    {
    }

    /// @brief Checks whether the active form is empty.
    /// @return Value of `empty()` on the active form.
    bool empty() const noexcept
    {
        return std::visit(
            [](const auto& inner) noexcept
            {
                return inner.empty();
            },
            keyShare_);
    }

    /// @brief Serializes the active form into @p output.
    /// @param[in] whoami Side (Client or Server); unused.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` otherwise.
    std::size_t serialize(Side /*whoami*/, nonstd::span<uint8_t> output) const noexcept
    {
        return std::visit(
            [output](const auto& inner) noexcept
            {
                return inner.serialize(output);
            },
            keyShare_);
    }

    /// @brief Parses the extension body for a given handshake message type.
    /// @param[in] side           Side (Client or Server); unused.
    /// @param[in] input          Wire bytes of the extension_data field.
    /// @param[in] handshakeType  One of ClientHello, ServerHello, HelloRetryRequest.
    /// @return DecodeError::None on success; error otherwise.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input,
                                   HandshakeType handshakeType) noexcept;

    /// @brief Sets the public key on the active ServerHello form.
    /// @param[in] key Public key to encode.
    /// @throws std::logic_error if the active form is not ServerHello.
    void setPublicKey(const Key* key);

    /// @brief Sets the public key by index on the active ClientHello form.
    /// @param[in] idx Index in `[0, size())`.
    /// @param[in] key Public key to encode.
    /// @throws std::logic_error if the active form is not ClientHello.
    /// @throws std::out_of_range if @p idx is out of range.
    void setPublicKey(std::size_t idx, const Key* key);

    /// @brief Reconstructs a public key from the active ClientHello or ServerHello form.
    /// @param[in] i Index (used only by ClientHello).
    /// @return Public key, or nullptr on unsupported group.
    /// @throws std::logic_error if the active form is HelloRetryRequest.
    crypto::KeyPtr getPublicKey(std::size_t i = 0) const;

    /// @brief Collects the offered groups of the active form into @p out.
    /// @param[out] out Destination vector; cleared and filled with offered groups.
    void offeredGroups(std::vector<crypto::GroupParams>& out) const;

    /// @brief Gets the selected group (ServerHello or HelloRetryRequest only).
    /// @return The selected group.
    /// @throws std::logic_error for the ClientHello form.
    crypto::GroupParams selectedGroup() const;

    /// @brief Retries the ClientHello offer against an HRR.
    /// @param[in] retryRequestKeyShare HRR form carrying the selected group.
    /// @param[in] supportedGroups      Groups advertised in the original ClientHello.
    /// @throws std::runtime_error if the HRR selected a group that was not offered,
    ///         or if the active forms are not `ClientHello` + `HelloRetryRequest`.
    void retryOffer(const KeyShare& retryRequestKeyShare, const std::vector<crypto::GroupParams>& supportedGroups);

    /// @brief Raw access to the active form (advanced / tests).
    /// @return Const reference to the active variant.
    const Variant& raw() const noexcept
    {
        return keyShare_;
    }

private:
    Variant keyShare_; ///< Active form.
};

} // namespace snet::tls