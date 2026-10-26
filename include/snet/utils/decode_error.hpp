#pragma once

#include <cstdint>
#include <string>
#include <system_error>

namespace snet::utils
{

/// @brief Errors that can occur while decoding TLS wire data.
///
/// Registered with `std::is_error_code_enum`, so an implicit conversion to
/// `std::error_code` is available. The underlying type is `std::uint8_t`
/// (1 byte) so `DecodeError` stays compact in hot-path structures.
enum class DecodeError : std::uint8_t
{
    None = 0,         ///< No error.
    NotEnoughBytes,   ///< `at_least`: fewer bytes than required.
    TrailingBytes,    ///< `assert_done`: input was not fully consumed.
    BadLengthSize,    ///< `get_length_field`: `len_bytes` not in {1, 2, 3}.
    SizeNotMultiple,  ///< `get_num_elems`: `byte_length % sizeof(T) != 0`.
    LengthOutOfRange, ///< `num_elems < min || num_elems > max`.
    AllocationFailed, ///< `resize_guarded`: `bad_alloc` was caught.
    MalformedMessage, ///< Malformed data in message.
};

/// @brief `std::error_category` for `DecodeError`.
///
/// Provides `name()` and `message()` so that `std::error_code::message()`
/// returns the same human-readable text as `DecodeError::toString()` used to.
class DecodeErrorCategory final : public std::error_category
{
public:
    /// @brief Gets the category name.
    /// @return `"snet.tls.decode"`.
    const char* name() const noexcept override
    {
        return "snet.tls.decode";
    }

    /// @brief Gets a human-readable message for @p ev.
    /// @param[in] ev Error value (cast from `DecodeError`).
    /// @return Message string.
    std::string message(int ev) const override
    {
        switch (static_cast<DecodeError>(ev))
        {
        case DecodeError::None:
            return "ok";
        case DecodeError::NotEnoughBytes:
            return "not enough bytes";
        case DecodeError::TrailingBytes:
            return "trailing bytes";
        case DecodeError::BadLengthSize:
            return "bad length size";
        case DecodeError::SizeNotMultiple:
            return "size not multiple of element";
        case DecodeError::LengthOutOfRange:
            return "length field outside parameters";
        case DecodeError::AllocationFailed:
            return "allocation failed";
        case DecodeError::MalformedMessage:
            return "malformed message";
        }
        return "unknown decode error";
    }
};

/// @brief Gets the singleton `DecodeErrorCategory` instance.
/// @return Reference to the category (stable for the lifetime of the program).
inline const std::error_category& GetDecodeErrorCategory() noexcept
{
    static DecodeErrorCategory instance;
    return instance;
}

/// @brief Builds a `std::error_code` from @p e.
/// @param[in] e Decode error code.
/// @return `std::error_code` in `GetDecodeErrorCategory()`.
inline std::error_code make_error_code(DecodeError e) noexcept
{
    return {static_cast<int>(e), GetDecodeErrorCategory()};
}

} // namespace snet::utils

namespace std
{

/// @brief Enables implicit conversion `DecodeError -> std::error_code`.
template <>
struct is_error_code_enum<snet::utils::DecodeError> : std::true_type
{
};

} // namespace std