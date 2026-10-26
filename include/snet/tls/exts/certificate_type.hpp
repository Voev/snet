#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// @brief Certificate types as defined in RFC 7250 / RFC 8446 §4.4.2.
///
/// Note: the wire field is a single byte; values 0 and 2 are currently
/// registered (X.509 and RawPublicKey). Other values are syntactically valid
/// but unsupported — the caller decides whether to reject them.
enum class CertificateType : uint8_t
{
    X509 = 0,         ///< X.509 certificate.
    RawPublicKey = 2, ///< Raw public key.
};

/// @brief Gets a human-readable name for @p t.
/// @param[in] t Certificate type.
/// @return Static string; `"Unknown"` for unrecognized values.
constexpr const char* toString(CertificateType t) noexcept
{
    switch (t)
    {
    case CertificateType::X509:
        return "X509";
    case CertificateType::RawPublicKey:
        return "RawPublicKey";
    }
    return "Unknown";
}

/// @brief Parses a name produced by `toString()`.
/// @param[in] s Name to parse.
/// @return Corresponding CertificateType.
/// @throws casket::RuntimeError on unknown input (config-level API, not hot path).
CertificateType certificateTypeFromString(const std::string& s);

namespace detail
{

/// @brief Parses the wire form of client/server `certificate_type` extension.
///   * Client side: `<1-byte length> <type byte>*`  (RFC 7250 §4.1)
///   * Server side: `<1-byte type>`                 (RFC 7250 §4.2)
/// @param[in] side  Side (Client or Server); selects the wire format.
/// @param[in] input Wire bytes of the extension_data field.
/// @param[out] out Destination vector; cleared and filled with parsed types.
/// @return DecodeError::None on success; a specific code otherwise. Never throws.
utils::DecodeError parseCertificateTypes(Side side, nonstd::span<const uint8_t> input,
                                         std::vector<CertificateType>& out) noexcept;

/// @brief Serializes @p types according to @p side.
/// @param[in] side   Side (Client or Server); selects the wire format.
/// @param[in] types  Certificate types to serialize.
/// @param[in] output Destination buffer.
/// @return Bytes written on success, `kSerializationFailed` if @p output is
///         too small or the list does not fit the wire length field.
std::size_t serializeCertificateTypes(Side side, nonstd::span<const CertificateType> types,
                                      nonstd::span<uint8_t> output) noexcept;

} // namespace detail

/// @brief Client Certificate Type extension (RFC 7250 §4.1).
class ClientCertificateType final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::ClientCertificateType.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ClientCertificateType;
    }

    /// @brief Default constructor.
    ClientCertificateType() noexcept = default;

    /// @brief Advertises support for the given certificate types (client side).
    /// @param[in] types Supported types; order preserved.
    explicit ClientCertificateType(std::vector<CertificateType> types)
        : certTypes_(std::move(types))
    {
    }

    /// @brief Server-side selection from the client's preferences.
    /// @param[in] fromClient       Client's advertised types.
    /// @param[in] serverPreference Server preference order; first match wins.
    /// @note If no match is found, the result is empty and `empty()` returns
    ///       `true` (the extension is omitted).
    ClientCertificateType(const ClientCertificateType& fromClient,
                          nonstd::span<const CertificateType> serverPreference);

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  Only X.509 is offered (RFC 7250 §4.1: omit the extension).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return certTypes_.size() == 1 && certTypes_.front() == CertificateType::X509;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); selects the wire format.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` otherwise.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        return detail::serializeCertificateTypes(side, certTypes_, output);
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); selects the wire format.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success; a specific code otherwise.
    ///         On failure the object is left empty (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        certTypes_.clear();
        return detail::parseCertificateTypes(side, input, certTypes_);
    }

    /// @brief Gets the advertised certificate types in wire order.
    /// @return View over the owned vector.
    nonstd::span<const CertificateType> types() const noexcept
    {
        return {certTypes_.data(), certTypes_.size()};
    }

    /// @brief Gets the single negotiated type (server side).
    /// @return First advertised type, or X.509 if the list is empty.
    /// @note Precondition: `!empty()`.
    CertificateType selectedCertificateType() const noexcept
    {
        return certTypes_.empty() ? CertificateType::X509 : certTypes_.front();
    }

    /// @brief Checks that the server's selection is among the client's offers.
    /// @param[in] fromServer Server's response to validate.
    /// @return DecodeError::None if the selection is valid,
    ///         DecodeError::LengthOutOfRange otherwise.
    utils::DecodeError validateSelection(const ClientCertificateType& fromServer) const noexcept;

private:
    std::vector<CertificateType> certTypes_; ///< Advertised types; wire order preserved.
};

/// @brief Server Certificate Type extension (RFC 7250 §4.2).
class ServerCertificateType final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::ServerCertificateType.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ServerCertificateType;
    }

    /// @brief Default constructor.
    ServerCertificateType() noexcept = default;

    /// @brief Advertises support for the given certificate types (server side).
    /// @param[in] types Supported types; order preserved.
    explicit ServerCertificateType(std::vector<CertificateType> types)
        : certTypes_(std::move(types))
    {
    }

    /// @brief Server-side selection from the client's preferences.
    /// @param[in] fromClient       Client's advertised types.
    /// @param[in] serverPreference Server preference order; first match wins.
    ServerCertificateType(const ServerCertificateType& fromClient,
                          nonstd::span<const CertificateType> serverPreference);

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  Only X.509 is offered (extension is omitted).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return certTypes_.size() == 1 && certTypes_.front() == CertificateType::X509;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); selects the wire format.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` otherwise.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        return detail::serializeCertificateTypes(side, certTypes_, output);
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); selects the wire format.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success; a specific code otherwise.
    ///         On failure the object is left empty (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        certTypes_.clear();
        return detail::parseCertificateTypes(side, input, certTypes_);
    }

    /// @brief Gets the advertised certificate types in wire order.
    /// @return View over the owned vector.
    nonstd::span<const CertificateType> types() const noexcept
    {
        return {certTypes_.data(), certTypes_.size()};
    }

    /// @brief Gets the single negotiated type (server side).
    /// @return First advertised type, or X.509 if the list is empty.
    /// @note Precondition: `!empty()`.
    CertificateType selectedCertificateType() const noexcept
    {
        return certTypes_.empty() ? CertificateType::X509 : certTypes_.front();
    }

    /// @brief Checks that the server's selection is among the client's offers.
    /// @param[in] fromServer Server's response to validate.
    /// @return DecodeError::None if the selection is valid,
    ///         DecodeError::LengthOutOfRange otherwise.
    utils::DecodeError validateSelection(const ServerCertificateType& fromServer) const noexcept;

private:
    std::vector<CertificateType> certTypes_; ///< Advertised types; wire order preserved.
};

} // namespace snet::tls