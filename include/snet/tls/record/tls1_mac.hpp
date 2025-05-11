#pragma once
#include <array>
#include <span>
#include <snet/crypto/typedefs.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/record/cipher_traits.hpp>

namespace snet::tls::v1
{

void checkTls1Mac(const CipherTraits& traits, uint64_t seq, RecordType recordType,
                  std::span<const uint8_t> macKey, std::span<const uint8_t> content,
                  std::span<const uint8_t> expectedMac, std::span<const uint8_t> iv);

void checkSsl3Mac(const CipherTraits& traits, uint64_t seq, RecordType recordType,
                  std::span<const uint8_t> macKey, std::span<const uint8_t> content,
                  std::span<const uint8_t> expectedMac);

} // namespace snet::tls::v1