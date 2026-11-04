/// @file
/// @brief Destination for outgoing bytes (TX side of a byte transport).

#pragma once

#include <cstddef>
#include <cstdint>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief Destination for outgoing bytes.
///
/// The TLS layer writes serialized records through this interface; the
/// concrete transport (TCP ring, mock, ...) is hidden behind it. This
/// keeps @c Session independent of any particular transport.
///
/// Contract:
///  - @c available() reports how many bytes can be accepted by
///    a single @c write() call.
///  - @c write() accepts exactly @c data.size() bytes, or none
///    (all-or-nothing). Returns @c false if the writer has no room.
///
/// @note The read path does not need a symmetric interface: incoming
///       bytes are pushed into @c Session::readRecords(span), so a
///       plain @c span<const uint8_t> is sufficient there.
class IByteWriter
{
public:
    virtual ~IByteWriter() = default;

    /// @brief Bytes that can be accepted by a single @c write() call.
    virtual std::size_t available() const noexcept = 0;

    /// @brief Accept exactly @c data.size() bytes, or none.
    /// @return true on success, false if the writer has no room.
    virtual bool write(nonstd::span<const std::uint8_t> data) noexcept = 0;
};

} // namespace snet::tls