#pragma once
#include <casket/nonstd/span.hpp>
#include <casket/utils/noncopyable.hpp>

#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct EncryptedExtensions final : public casket::NonCopyable
{
    EncryptedExtensions() = default;

    ~EncryptedExtensions() noexcept = default;

    EncryptedExtensions(EncryptedExtensions&& other) noexcept = default;

    EncryptedExtensions& operator=(EncryptedExtensions&& other) noexcept = default;

    void deserialize(nonstd::span<const uint8_t> message);

    size_t serialize(nonstd::span<uint8_t> buffer) const;

    Extensions extensions;
};

} // namespace snet::tls