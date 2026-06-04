#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "encrylib/secure_bytes.h"
#include "encrylib/sm4.h"

namespace encrylib {

struct EncryptedBlob {
  Block16 nonce{};
  Bytes ciphertext;
  Hash32 tag{};
};

Bytes random_bytes(std::size_t size);
Block16 random_block16();
Hash32 random_hash32();

bool constant_time_equal(std::span<const std::uint8_t> a,
                         std::span<const std::uint8_t> b) noexcept;

Bytes derive_bytes(std::span<const std::uint8_t> key,
                   const std::string& info,
                   std::size_t output_size);
Hash32 derive_key32(std::span<const std::uint8_t> key,
                    const std::string& info);

EncryptedBlob encrypt_blob(std::span<const std::uint8_t> encryption_key,
                           std::span<const std::uint8_t> mac_key,
                           std::span<const std::uint8_t> plaintext,
                           std::span<const std::uint8_t> aad);
Bytes decrypt_blob(std::span<const std::uint8_t> encryption_key,
                   std::span<const std::uint8_t> mac_key,
                   const EncryptedBlob& blob,
                   std::span<const std::uint8_t> aad);

}  // namespace encrylib
