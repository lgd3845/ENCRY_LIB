#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "encrylib/secure_bytes.h"

namespace encrylib {

class Sm4 {
 public:
  explicit Sm4(std::span<const std::uint8_t> key);
  Sm4(const Sm4&) = delete;
  Sm4& operator=(const Sm4&) = delete;
  Sm4(Sm4&& other) noexcept;
  Sm4& operator=(Sm4&& other) noexcept;
  ~Sm4();

  Block16 encrypt_block(const Block16& block) const;
  Block16 decrypt_block(const Block16& block) const;
  void ctr_crypt(const Block16& nonce,
                 std::span<const std::uint8_t> input,
                 std::span<std::uint8_t> output) const;
  void ctr_crypt_in_place(const Block16& nonce,
                          std::span<std::uint8_t> data) const;

 private:
  std::array<std::uint32_t, 32> round_keys_{};
};

}  // namespace encrylib
