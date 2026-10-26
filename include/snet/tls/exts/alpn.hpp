#pragma once

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <iterator>
#include <string>
#include <vector>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/string_view.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// @brief ALPN (Application-Layer Protocol Negotiation) extension (RFC 7301).
///
/// Storage is a single flat `std::vector<char>` that mirrors the wire
/// layout (`<1-byte len><bytes>...`) plus a parallel `offsets_` vector for
/// O(1) iteration. One allocation per extension; capacity is reused across
/// handshakes via `deserialize` on a pre-populated instance.
class ALPN final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::AppLayerProtocolNegotiation.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::AppLayerProtocolNegotiation;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  No protocols stored (extension is skipped on wire).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return offsets_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold `2 + buf_.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small or the protocol list exceeds 65535 bytes.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t bodyLen = buf_.size();
        if (bodyLen > 0xFFFF)
        {
            return kSerializationFailed;
        }

        if (output.size_bytes() < 2 + bodyLen)
        {
            return kSerializationFailed;
        }

        const auto length16 = static_cast<std::uint16_t>(bodyLen);
        output[0] = casket::get_byte<0>(length16);
        output[1] = casket::get_byte<1>(length16);

        if (bodyLen)
        {
            std::memcpy(output.data() + 2, buf_.data(), length16);
        }

        return 2 + bodyLen;
    }

    /// @brief Default constructor.
    ALPN() noexcept = default;

    /// @brief Constructs from a single protocol (server side).
    /// @param[in] protocol Protocol name; must be 1..255 bytes.
    /// @throws std::invalid_argument if @p protocol is empty or longer than 255.
    /// @throws std::bad_alloc on allocation failure.
    explicit ALPN(nonstd::string_view protocol)
    {
        if (protocol.empty() || protocol.size() > 255)
        {
            throw std::invalid_argument("ALPN protocol name must be 1..255 bytes");
        }
        if (!appendProtocol(protocol))
        {
            throw std::bad_alloc();
        }
    }

    /// @brief Constructs from a list of protocols (client side).
    /// @param[in] protocols Offered protocol names; each 1..255 bytes.
    /// @throws std::bad_alloc on allocation failure.
    /// @throws std::invalid_argument if any name is empty or longer than 255.
    explicit ALPN(const std::vector<std::string>& protocols);

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); server response must list
    ///                  exactly one protocol.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success, otherwise a specific code.
    ///         On failure the object is left empty (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept;

    /// @brief Iterates protocol names without allocating.
    class ProtocolRange
    {
    public:
        /// @brief Forward iterator over `nonstd::string_view` protocol names.
        struct iterator
        {
            using iterator_category = std::forward_iterator_tag; ///< Iterator category.
            using value_type = nonstd::string_view;              ///< Value type.
            using difference_type = std::ptrdiff_t;              ///< Distance type.
            using pointer = const value_type*;                   ///< Pointer type.
            using reference = value_type;                        ///< Reference type.

            const ALPN* owner = nullptr; ///< Owning ALPN instance.
            std::size_t idx = 0;         ///< Index into `owner->offsets_`.

            /// @brief Dereferences to the protocol name at @p idx.
            /// @return View over the protocol name.
            reference operator*() const noexcept
            {
                return owner->protocolAt(idx);
            }

            /// @brief Advances to the next protocol.
            /// @return Reference to `*this`.
            iterator& operator++() noexcept
            {
                ++idx;
                return *this;
            }

            /// @brief Post-increments; returns a copy of the previous position.
            /// @return Iterator copy before advancing.
            iterator operator++(int) noexcept
            {
                iterator t = *this;
                ++idx;
                return t;
            }

            /// @brief Equality by index.
            bool operator==(const iterator& o) const noexcept
            {
                return idx == o.idx;
            }

            /// @brief Inequality by index.
            bool operator!=(const iterator& o) const noexcept
            {
                return idx != o.idx;
            }
        };

        /// @brief Iterator to the first protocol.
        iterator begin() const noexcept
        {
            return {owner_, 0};
        }

        /// @brief Iterator past the last protocol.
        iterator end() const noexcept
        {
            return {owner_, owner_->offsets_.size()};
        }

    private:
        friend class ALPN;
        explicit ProtocolRange(const ALPN* o) noexcept
            : owner_(o)
        {
        }
        const ALPN* owner_; ///< Owning ALPN instance.
    };

    /// @brief Gets a range of protocol names in wire order.
    /// @return View-like range over `nonstd::string_view` names.
    ProtocolRange protocols() const noexcept
    {
        return ProtocolRange(this);
    }

    /// @brief Gets the single protocol (server side, after a successful parse).
    /// @return View over the first protocol; empty if none.
    nonstd::string_view singleProtocol() const noexcept
    {
        return offsets_.empty() ? nonstd::string_view{} : protocolAt(0);
    }

    /// @brief Gets the number of stored protocols.
    /// @return Protocol count.
    std::size_t size() const noexcept
    {
        return offsets_.size();
    }

private:
    /// @brief Returns a view over the protocol at index @p i.
    /// @param[in] i Index in the range `[0, offsets_.size())`.
    /// @return View over the protocol bytes.
    nonstd::string_view protocolAt(std::size_t i) const noexcept
    {
        const std::size_t off = offsets_[i];
        const auto len = static_cast<std::uint8_t>(buf_[off]);
        return {buf_.data() + off + 1, len};
    }

    /// @brief Appends a protocol to the flat buffer.
    /// @param[in] p Protocol name; must be 1..255 bytes.
    /// @return true on success, false on OOM or invalid length.
    ///         On failure the object is left in a consistent (empty) state.
    bool appendProtocol(nonstd::string_view p) noexcept;

    /// @brief Clears the flat buffer and offsets, releasing no capacity.
    void clear() noexcept
    {
        buf_.clear();
        offsets_.clear();
    }

    std::vector<char> buf_;              ///< Flat wire layout: `[len:1][bytes:len]...`.
    std::vector<std::uint16_t> offsets_; ///< Offset of each `[len:1]` entry in `buf_`.
};

} // namespace snet::tls