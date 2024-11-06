/// @file
/// @brief Общий тип исключения для ошибок в криптографии

#pragma once

#include <string>
#include <system_error>
#include <stdexcept>

#include <snet/tls/error_code.hpp>

namespace snet::tls {

/// @brief Основной класс для исключений crypto_unit
class Exception final : public std::system_error {
public:
    /// @brief Конструктор
    ///
    /// @param ec Код ошибки
    explicit Exception(std::error_code ec)
        : std::system_error(ec) {
    }

    /// @brief Конструктор
    ///
    /// @param ec Код ошибки
    /// @param what Дополнительное сообщение
    explicit Exception(std::error_code ec, std::string what)
        : std::system_error(ec, what.data()) {
    }
};

/// @brief Бросает исключение если @p exprResult истинно
///
/// @param exprResult Результат анализируемого выражения
///
/// @code{.cpp}
/// /* ПРИМЕР */
/// auto* somePointer = new (std::nothrow) int;
/// Exception::throwIfTrue(somePointer == nullptr);
/// @endcode
inline void ThrowIfTrue(bool exprResult) {
    if (exprResult) {
        throw Exception(GetLastError());
    }
}

/// @brief Бросает исключение если @p exprResult истинно
///
/// @param exprResult Результат анализируемого выражения
/// @param msg Дополнительное сообщение
inline void ThrowIfTrue(bool exprResult, std::string msg) {
    if (exprResult) {
        throw Exception(GetLastError(), msg);
    }
}

/// @brief Бросает исключение если @p exprResult ложно
///
/// @param exprResult Результат анализируемого выражения
///
/// @code{.cpp}
/// /* ПРИМЕР */
/// void* inputData = nullptr;
/// SomeValidator validator;
/// Exception::throwIfFalse(validator.isValid(inputData));
/// @endcode
inline void ThrowIfFalse(bool exprResult) {
    return ThrowIfTrue(!exprResult);
}

/// @brief Бросает исключение если @p exprResult ложно
///
/// @param exprResult Результат анализируемого выражения
/// @param msg Дополнительное сообщение
inline void ThrowIfFalse(bool exprResult, std::string msg) {
    return ThrowIfTrue(!exprResult, std::move(msg));
}

} // namespace snet::tls
