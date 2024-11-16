/// @brief Объявление класса сообщения протокола оповещения (Alert).

#pragma once
#include <string>
#include <vector>
#include <span>

namespace snet::tls
{

/// @brief Класс сообщения протокола оповещения.
class Alert final
{
public:
    /// @brief Описание сообщения оповещения.
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
        None = 256, // Псевдо-значение для отслеживания корректности.
    };

    /// @brief Конструктор по умолчанию.
    Alert();

    /// @brief Деструктор.
    ~Alert() noexcept;

    /// @brief Конструктор копирования.
    /// @param other Константная ссылка на сообщение оповещения.
    Alert(const Alert& other);

    /// @brief Конструктор перемещения.
    /// @param other rvalue-ссылка на сообщение оповещения.
    Alert(Alert&& other) noexcept;

    /// @brief Оператор копирования.
    /// @param other Константная ссылка на сообщение оповещения.
    /// @return Ссылка на сообщение оповещения.
    Alert& operator=(const Alert& other);

    /// @brief Оператор перемещения.
    /// @param other rvalue-ссылка на сообщение оповещения.
    /// @return Ссылка на сообщение оповещения.
    Alert& operator=(Alert&& other) noexcept;

    /// @brief Конструктор, формирующий сообщение оповещения из явного описания и флага критичности.
    /// @param description Описание сообщения оповещения.
    /// @param fatal Флаг критичности сообщения оповещения.
    Alert(Description description, bool fatal = false);

    /// @brief Конструктор, десериализующий набор байт в сообщение оповещения.
    /// @param buf Набор байт.
    explicit Alert(std::span<const uint8_t> buf);

    /// @brief Метод проверки критичности сообщения.
    /// @retval true - сообщение Alert критическое.
    /// @retval false - иначе.
    bool isFatal() const noexcept;

    /// @brief Метод проверки корректности сообщения.
    /// @retval true - если описание оповещения было задано.
    /// @retval false - иначе.
    bool isValid() const noexcept;

    /// @brief Метод получения описания оповещения
    /// @return
    Description description() const noexcept;

    /// @brief Метод преобразования в строковое представление.
    /// @return Строковое представление.
    std::string toString() const;

    /// @brief Метод сериализации сообщения оповещения в набор байт.
    /// @return Набор байт.
    std::vector<uint8_t> serialize() const;

private:
    bool fatal_;
    Description description_;
};

} // namespace snet::tls
