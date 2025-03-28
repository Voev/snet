#pragma once

#include <string_view>
#include <snet/crypto/pointers.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::crypto
{

/// @brief Реализует операции по загрузке объектов из хранилища OSSL_STORE
class StoreLoader final : public utils::NonCopyable
{
public:
    /// @brief Конструктор
    /// @param uri Путь до объекта в хранилище
    /// @param meth UI_METHOD для доступа к хранилищу (может быть NULL)
    /// @param data Дополнительные данные передаваемые в @p meth (может быть NULL)
    StoreLoader(std::string_view uri, const UiMethod* meth, void* data);

    /// @brief Деструктор
    ~StoreLoader() = default;

    /// @brief Проверяет состояние хранилища
    /// @return true - если хранилище в невалидном состояния, false - иначе
    bool isError();

    /// @brief Проверяет достигли ли мы конца хранилища (EOF)
    /// @return true - если конец достигнут, false - иначе
    bool finished();

    /// @brief Проверяет, что внутренний интератор в хранилище смотрит на объект типа @p type
    /// @param type Элемент перечисления OSSL_STORE_INFO
    /// @see https://www.openssl.org/docs/man3.0/man3/OSSL_STORE_INFO_get1_CERT.html
    void expect(int type);

    /// @brief Выполняет загрузку объекта типа @p type из хранилища
    /// @note Пере загрузкой вызывает StoreLoader::expect(), так что нет необходимости делать это
    /// вручную
    /// @param type Элемент перечисления OSSL_STORE_INFO
    /// @return Возвращает указатель на дескриптор объекта в хранилище
    StoreInfoPtr load(int type);

private:
    StoreCtxPtr ctx_;
};

} // namespace snet::crypto
