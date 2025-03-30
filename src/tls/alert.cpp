/// @brief Определение класса сообщения протокола оповещения (Alert).

#include <snet/tls/alert.hpp>
#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

namespace
{

const char* DescriptionToString(const Alert::Description description)
{
    switch (description)
    {
    case Alert::Description::CloseNotify:
        return "close_notify";
    case Alert::Description::UnexpectedMessage:
        return "unexpected_message";
    case Alert::Description::BadRecordMac:
        return "bad_record_mac";
    case Alert::Description::DecryptionFailed:
        return "decryption_failed";
    case Alert::Description::RecordOverflow:
        return "record_overflow";
    case Alert::Description::DecompressionFailure:
        return "decompression_failure";
    case Alert::Description::HandshakeFailure:
        return "handshake_failure";
    case Alert::Description::NoCertificate:
        return "no_certificate";
    case Alert::Description::BadCertificate:
        return "bad_certificate";
    case Alert::Description::UnsupportedCertificate:
        return "unsupported_certificate";
    case Alert::Description::CertificateRevoked:
        return "certificate_revoked";
    case Alert::Description::CertificateExpired:
        return "certificate_expired";
    case Alert::Description::CertificateUnknown:
        return "certificate_unknown";
    case Alert::Description::IllegalParameter:
        return "illegal_parameter";
    case Alert::Description::UnknownCA:
        return "unknown_ca";
    case Alert::Description::AccessDenied:
        return "access_denied";
    case Alert::Description::DecodeError:
        return "decode_error";
    case Alert::Description::DecryptError:
        return "decrypt_error";
    case Alert::Description::ExportRestriction:
        return "export_restriction";
    case Alert::Description::ProtocolVersion:
        return "protocol_version";
    case Alert::Description::InsufficientSecurity:
        return "insufficient_security";
    case Alert::Description::InternalError:
        return "internal_error";
    case Alert::Description::InappropriateFallback:
        return "inappropriate_fallback";
    case Alert::Description::UserCanceled:
        return "user_canceled";
    case Alert::Description::NoRenegotiation:
        return "no_renegotiation";
    case Alert::Description::MissingExtension:
        return "missing_extension";
    case Alert::Description::UnsupportedExtension:
        return "unsupported_extension";
    case Alert::Description::CertificateUnobtainable:
        return "certificate_unobtainable";
    case Alert::Description::UnrecognizedName:
        return "unrecognized_name";
    case Alert::Description::BadCertificateStatusResponse:
        return "bad_certificate_status_response";
    case Alert::Description::BadCertificateHashValue:
        return "bad_certificate_hash_value";
    case Alert::Description::UnknownPSKIdentity:
        return "unknown_psk_identity";
    case Alert::Description::CertificateRequired:
        return "certificate_required";
    case Alert::Description::NoApplicationProtocol:
        return "no_application_protocol";
    case Alert::Description::None:
        return "none";
    }

    return nullptr;
}

} // namespace

Alert::Alert()
    : fatal_(false)
    , description_(Description::None)
{
}

Alert::~Alert() noexcept = default;

Alert::Alert(const Alert& other) = default;

Alert::Alert(Alert&& other) noexcept = default;

Alert& Alert::operator=(const Alert& other) = default;

Alert& Alert::operator=(Alert&& other) noexcept = default;

Alert::Alert(Description description, bool fatal)
    : fatal_(fatal)
    , description_(description)
{
}

Alert::Alert(const int code) {
    ThrowIfTrue(code < 0 || code > 0xFFFF, "Bad value (" + std::to_string(code) + ") for TLS alert message");

    std::uint8_t level = (code >> 8) & 0xFF;
    std::uint8_t description = code & 0xFF;

    ThrowIfTrue(level < 1 || level > 2, "Bad code for TLS alert level");

    fatal_ = (level == 2);
    description_ = static_cast<Description>(description);
}

Alert::Alert(std::span<const uint8_t> buf)
{
    ThrowIfTrue(buf.size() != 2,
                "Bad size (" + std::to_string(buf.size()) + ") for TLS alert message");

    ThrowIfFalse(buf[0] == 1 || buf[0] == 2, "Bad code for TLS alert level");

    fatal_ = (buf[0] == 2);
    description_ = static_cast<Description>(buf[1]);
}

bool Alert::isFatal() const noexcept
{
    return fatal_;
}

bool Alert::isValid() const noexcept
{
    return (description_ != Alert::Description::None);
}

Alert::Description Alert::description() const noexcept
{
    return description_;
}

std::string Alert::toString() const
{
    const char* knownAlert = DescriptionToString(description());
    if (knownAlert)
    {
        return std::string(knownAlert);
    }

    return "unknown_alert_" + std::to_string(static_cast<size_t>(description()));
}

std::vector<uint8_t> Alert::serialize() const
{
    if (isValid())
    {
        std::vector<uint8_t> message(2);
        message[0] = isFatal() ? 2 : 1;
        message[1] = static_cast<uint8_t>(description());
        return message;
    }
    return std::vector<uint8_t>();
}

} // namespace snet::tls
