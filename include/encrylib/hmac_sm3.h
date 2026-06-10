#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "encrylib/secure_bytes.h"
#include "encrylib/sm3.h"

namespace encrylib {

class HmacSm3 {
 public:
  explicit HmacSm3(std::span<const std::uint8_t> key);
  HmacSm3(const HmacSm3&) = delete;
  HmacSm3& operator=(const HmacSm3&) = delete;
  HmacSm3(HmacSm3&& other) noexcept;
  HmacSm3& operator=(HmacSm3&& other) noexcept;
  ~HmacSm3();

  void update(std::span<const std::uint8_t> data);
  Hash32 final();

 private:
  Sm3 inner_;
  std::array<std::uint8_t, 64> outer_pad_{};
};

Hash32 hmac_sm3(std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> data);
Bytes hkdf_sm3(std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> info,
               std::size_t output_size);
SecureBytes pbkdf2_hmac_sm3(std::span<const std::uint8_t> password,
                            std::span<const std::uint8_t> salt,
                            std::uint32_t iterations,
                            std::size_t output_size);

}  // namespace encrylib
