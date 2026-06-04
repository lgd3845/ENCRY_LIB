#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "encrylib/secure_bytes.h"

namespace encrylib {

class Sm3 {
 public:
  Sm3();

  void update(std::span<const std::uint8_t> data);
  void update(const std::uint8_t* data, std::size_t size);
  Hash32 final();
  void reset();

 private:
  void compress(const std::uint8_t block[64]);

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffer_size_ = 0;
  std::uint64_t total_bytes_ = 0;
};

Hash32 sm3(std::span<const std::uint8_t> data);
Hash32 sm3_string(const std::string& data);
std::string hex_encode(std::span<const std::uint8_t> data);
Bytes hex_decode(const std::string& hex);

}  // namespace encrylib
