/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <variant>
#include <cstring>
#include <cassert>
#include <casket/nonstd/span.hpp>
#include <casket/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

#include <snet/tls/version.hpp>
#include <snet/tls/msgs/handshake_message.hpp>

namespace snet::tls
{

/// @brief A single TLS record: header, plaintext/ciphertext views, and
///        optional handshake payload.
///
/// @details The record is a state machine traversed by @c Session and
///          @c RecordLayer. Read path: @c deserializeHeader → @c initCiphertext
///          → @c markDecrypted → @c deserializeHandshake. Write path:
///          @c serializeHandshake/@c serializeChangeCipherSpec → @c markEncrypted
///          → @c serializeHeader. Buffers are owned inline; the @c ciphertext_
///          and @c plaintext_ spans are views (zero-copy in the read path).
class Record
{
public:
    /// @brief Lifecycle phase of the record.
    ///
    /// @details Only @c Reading is an in-flight state; all others are stable
    ///          and report @c isFullyAssembled() == true.
    enum class State : uint8_t
    {
        Empty,      ///< Freshly reset; no data.
        Reading,    ///< Assembling ciphertext from network chunks.
        Read,       ///< Ciphertext fully assembled; ready to decrypt.
        Decrypted,  ///< Plaintext available (post-decrypt).
        Writing,    ///< Plaintext available; no encryption required.
        Encrypting, ///< Plaintext available; must be encrypted before send.
        Encrypted,  ///< Ciphertext available; ready to serialize.
    };

    /// @brief Construct an empty record in State::Empty.
    Record() noexcept;

    /// @brief Construct a record with a preset type.
    /// @param[in] type Initial record type.
    explicit Record(RecordType type) noexcept;

    /// @brief Get the current lifecycle state.
    /// @return Current State value.
    State getState() const noexcept
    {
        return state_;
    }

    /// @brief Check whether the record has finished assembling.
    /// @return true unless the record is still in State::Reading.
    inline bool isFullyAssembled() const noexcept
    {
        return state_ != State::Reading;
    }

    /// @brief Get the record type (wire or inner, depending on phase).
    /// @return Current record type.
    inline RecordType getType() const noexcept
    {
        return type_;
    }

    /// @brief Get the record protocol version.
    /// @return Protocol version stored in the header.
    inline ProtocolVersion getVersion() const noexcept
    {
        return version_;
    }

    /// @brief Get the current logical length.
    /// @return Ciphertext length on read path; body length after transform
    ///         on write path.
    inline uint16_t getLength() const noexcept
    {
        return currentLength_;
    }

    /// @brief Check whether plaintext is currently valid.
    /// @return true in states Decrypted, Writing, Encrypting.
    inline bool isPlaintext() const noexcept
    {
        return state_ == State::Decrypted || state_ == State::Writing || state_ == State::Encrypting;
    }

    /// @brief Check whether the record requires encryption before send.
    /// @return true only in State::Encrypting.
    inline bool mustBeEncrypted() const noexcept
    {
        return state_ == State::Encrypting;
    }

    /// @brief Get the ciphertext view (const).
    /// @return Span over the current ciphertext (may alias external memory
    ///         in the zero-copy read path).
    inline nonstd::span<const uint8_t> getCiphertext() const noexcept
    {
        return ciphertext_;
    }

    /// @brief Get the plaintext view (const).
    /// @return Span over the current plaintext.
    inline nonstd::span<const uint8_t> getPlaintext() const noexcept
    {
        return plaintext_;
    }

    /// @brief Get the plaintext view (mutable).
    /// @return Mutable span over the current plaintext.
    inline nonstd::span<uint8_t> getPlaintext() noexcept
    {
        return plaintext_;
    }

    /// @brief Get the plaintext view with the write-side data offset applied.
    /// @return Span starting at @c dataStartOffset_ (excludes AEAD prefix).
    inline nonstd::span<uint8_t> getPlaintextOffset() noexcept
    {
        return plaintext_.subspan(dataStartOffset_);
    }

    /// @brief Reset the record to State::Empty and clear all buffers.
    void reset() noexcept;

    /// @brief Initialize the plaintext buffer by copying input data.
    /// @param[in] plaintext Source bytes to copy into the plaintext buffer.
    /// @return Total plaintext length (including @c dataStartOffset_).
    size_t initPlaintext(nonstd::span<const uint8_t> plaintext);

    /// @brief Set the write-side data offset (AEAD prefix length).
    /// @param[in] offset Offset in bytes.
    void setDataOffset(size_t offset) noexcept
    {
        dataStartOffset_ = offset;
    }

    /// @brief Append incoming ciphertext bytes; switches to zero-copy when
    ///        the whole record fits in a single chunk.
    /// @param[in] data Incoming ciphertext bytes.
    /// @return Number of bytes consumed.
    size_t initCiphertext(nonstd::span<const uint8_t> data) noexcept;

    /// @brief Parse the 5-byte TLS record header.
    /// @param[in] data Span of at least @c TLS_HEADER_SIZE bytes.
    /// @throws std::exception on malformed header or oversized length.
    void deserializeHeader(nonstd::span<const uint8_t> data);

    /// @brief Serialize the TLS record header from current state.
    /// @param[out] output Span of at least @c TLS_HEADER_SIZE bytes.
    /// @return Number of bytes written (@c TLS_HEADER_SIZE).
    size_t serializeHeader(nonstd::span<uint8_t> output);

    /// @brief Deserialize the handshake message from plaintext bytes.
    /// @param[in] input Handshake payload (plaintext).
    /// @param[in] metaInfo Session metadata used for decoding.
    /// @return Error code; on success updates the handshake variant.
    std::error_code deserializeHandshake(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serialize a handshake message into the plaintext buffer.
    /// @param[in] handshake Handshake message to serialize (moved).
    /// @param[in] sideIndex Endpoint index (0 = client, 1 = server).
    /// @param[in] session Session used for record version and offsets.
    /// @return Total plaintext length.
    size_t serializeHandshake(HandshakeMessage&& handshake, int8_t sideIndex, const Session& session);

    /// @brief Serialize a ChangeCipherSpec record.
    /// @param[in] version Protocol version to store in the header.
    /// @return Length of the serialized body (1 byte).
    size_t serializeChangeCipherSpec(const ProtocolVersion& version);

    /// @brief Get the type of the stored handshake message.
    /// @return Handshake type (valid only for Handshake records).
    inline HandshakeType getHandshakeType() const
    {
        return handshake_.getType();
    }

    /// @brief Get a typed handshake payload.
    /// @tparam T Handshake message type (ClientHello, ServerHello, ...).
    /// @return Const reference to the stored message.
    template <typename T>
    const T& getHandshake() const
    {
        return handshake_.get<T>();
    }

    /// @brief Raw plaintext buffer (full capacity).
    /// @return Mutable span over @c plaintextBuffer_.
    /// @note Used as output buffer for decryption (CBC/AEAD in-place).
    ///       Not the current plaintext view; use @c getPlaintext() /
    ///       @c setPlaintextLength().
    nonstd::span<uint8_t> mutablePlaintextBuffer() noexcept
    {
        return plaintextBuffer_;
    }

    /// @brief Current plaintext view (mutable).
    /// @return Mutable span over @c plaintext_.
    /// @note Used for in-place encryption of the plaintext payload.
    nonstd::span<uint8_t> mutablePlaintext() noexcept
    {
        return plaintext_;
    }

    /// @brief Set the current plaintext view length.
    /// @param[in] len New length; must not exceed @c plaintextBuffer_.size().
    /// @note Used for TLS 1.3 inner-content-type append (+1) / strip (-1).
    void setPlaintextLength(size_t len) noexcept;

    /// @brief Publish decrypted plaintext and transition to State::Decrypted.
    /// @param[in] pt Plaintext range; must lie within @c plaintextBuffer_.
    void markDecrypted(nonstd::span<uint8_t> pt) noexcept;

    /// @brief Raw ciphertext buffer (full capacity).
    /// @return Mutable span over @c ciphertextBuffer_.
    /// @note Used as output buffer for encryption (TLS 1.3).
    nonstd::span<uint8_t> mutableCiphertextBuffer() noexcept
    {
        return ciphertextBuffer_;
    }

    /// @brief Publish encrypted ciphertext and transition to State::Encrypted.
    /// @param[in] ct Ciphertext range; may point into @c ciphertextBuffer_ or
    ///               @c plaintextBuffer_ (TLS 1.2 AEAD in-place).
    void markEncrypted(nonstd::span<const uint8_t> ct) noexcept;

    /// @brief Mutable ciphertext view.
    /// @return Mutable span over @c ciphertext_.
    /// @warning In the zero-copy read path @c ciphertext_ may alias a
    ///          caller-owned (const) buffer; writing through this view is UB
    ///          unless the caller guarantees mutability. Currently used only
    ///          by the TLS 1.2 AEAD in-place decrypt path.
    nonstd::span<uint8_t> mutableCiphertext() noexcept;

    /// @brief Override the wire record type (TLS 1.3 outer/inner type).
    /// @param[in] type New wire type.
    void setWireType(RecordType type) noexcept
    {
        type_ = type;
    }

private:
    /// @brief Set the lifecycle state directly.
    /// @param[in] s New state.
    void setState(State s) noexcept
    {
        state_ = s;
    }

private:
    RecordType type_;                                           ///< Wire or inner record type.
    ProtocolVersion version_;                                   ///< Protocol version from the header.
    std::array<uint8_t, MAX_CIPHERTEXT_SIZE> ciphertextBuffer_; ///< Inline ciphertext storage.
    std::array<uint8_t, MAX_PLAINTEXT_SIZE> plaintextBuffer_;   ///< Inline plaintext storage.
    HandshakeMessage handshake_;                                ///< Parsed/constructed handshake message.
    size_t currentLength_;                                      ///< Current logical length (bytes).
    size_t expectedLength_;                                     ///< Target length (ciphertext on read, body on write).
    size_t dataStartOffset_ = 0;                                ///< Write-side AEAD prefix length.
    nonstd::span<const std::uint8_t> ciphertext_;               ///< Ciphertext view (may alias external buffer).
    nonstd::span<std::uint8_t> plaintext_;                      ///< Plaintext view.
    State state_;                                               ///< Lifecycle state.
};

} // namespace snet::tls