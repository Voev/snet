#pragma once
#include <span>
#include <snet/tls/extensions.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls::msg
{

struct EncryptedExtensions final : public utils::NonCopyable
{
    EncryptedExtensions() = default;

    ~EncryptedExtensions() noexcept = default;

    EncryptedExtensions(EncryptedExtensions&& other) noexcept = default;

    EncryptedExtensions& operator=(EncryptedExtensions&& other) noexcept = default;

    void deserialize(std::span<const uint8_t> message);

    size_t serialize(std::span<uint8_t> buffer) const;

    Extensions extensions;
};

} // namespace snet::tls::msg