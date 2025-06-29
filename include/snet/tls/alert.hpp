/// @file
/// @brief Declaration of the Alert protocol message class.

#pragma once
#include <string>
#include <vector>
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief Alert protocol message class.
class Alert final
{
public:
    /// @brief Alert message description.
    enum Description
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailed = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificate = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCA = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestriction = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        NoRenegotiation = 100,
        MissingExtension = 109,
        UnsupportedExtension = 110,
        CertificateUnobtainable = 111,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        BadCertificateHashValue = 114,
        UnknownPSKIdentity = 115,
        CertificateRequired = 116,
        NoApplicationProtocol = 120,
        None = 256, // Pseudo-value for tracking correctness.
    };

    /// @brief Default constructor.
    Alert();

    /// @brief Destructor.
    ~Alert() noexcept;

    /// @brief Copy constructor.
    /// @param other Constant reference to the alert message.
    Alert(const Alert& other);

    /// @brief Move constructor.
    /// @param other rvalue reference to the alert message.
    Alert(Alert&& other) noexcept;

    /// @brief Copy assignment operator.
    /// @param other Constant reference to the alert message.
    /// @return Reference to the alert message.
    Alert& operator=(const Alert& other);

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the alert message.
    /// @return Reference to the alert message.
    Alert& operator=(Alert&& other) noexcept;

    /// @brief Constructor that forms an alert message from a specific description and fatal flag.
    /// @param description Alert message description.
    /// @param fatal Alert message fatal flag.
    Alert(Description description, bool fatal = false);

    Alert(const int code);

    /// @brief Constructor that deserializes a byte array into an alert message.
    /// @param buf Byte array.
    explicit Alert(nonstd::span<const uint8_t> buf);

    /// @brief Method to check if the alert message is fatal.
    /// @retval true - if the Alert message is fatal.
    /// @retval false - otherwise.
    bool isFatal() const noexcept;

    /// @brief Method to check if the alert message is valid.
    /// @retval true - if the alert description was set.
    /// @retval false - otherwise.
    bool isValid() const noexcept;

    /// @brief Method to get the alert description.
    /// @return Alert description.
    Description description() const noexcept;

    /// @brief Method to convert to a string representation.
    /// @return String representation.
    std::string toString() const;

    /// @brief Method to serialize the alert message into a byte array.
    /// @return Byte array.
    std::vector<uint8_t> serialize() const;

private:
    bool fatal_;
    Description description_;
};

} // namespace snet::tls
