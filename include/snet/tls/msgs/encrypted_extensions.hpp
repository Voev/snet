#pragma once
#include <snet/cpp_port/span.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

struct EncryptedExtensions final : public utils::NonCopyable
{
    EncryptedExtensions() = default;

    ~EncryptedExtensions() noexcept = default;

    EncryptedExtensions(EncryptedExtensions&& other) noexcept = default;

    EncryptedExtensions& operator=(EncryptedExtensions&& other) noexcept = default;

    void deserialize(cpp::span<const uint8_t> message);

    size_t serialize(cpp::span<uint8_t> buffer) const;

    Extensions extensions;
};

} // namespace snet::tls