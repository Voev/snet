#pragma once
#include <span>
#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Загружает ключ из хранилища
///
/// @param uri URI для получения ключа из хранилища
/// @param meth UI_METHOD, реализующий процедуры получения доступа к хранилищу
/// @param data Дополнительные данные для @p meth
///
/// @return Возвращает указатель на ключ
EvpPkeyPtr LoadPrivateKey(const std::string& uri, const UI_METHOD* meth, void* data);

/// @brief Загрузает ключ из хранилища
///
/// @param uri URI для получения ключа из хранилища
///
/// @return Возваращает указатель на ключ
EvpPkeyPtr LoadPrivateKey(const std::string& uri);

EvpPkeyPtr DeserializePrivateKey(std::span<const uint8_t> buffer);

} // namespace snet::tls