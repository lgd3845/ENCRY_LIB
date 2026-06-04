#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace encrylib {

void secure_zero(void* data, std::size_t size) noexcept;

class SecureBytes {
 public:
  SecureBytes() = default;
  explicit SecureBytes(std::size_t size);
  explicit SecureBytes(std::vector<std::uint8_t> bytes);
  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;
  SecureBytes(SecureBytes&& other) noexcept;
  SecureBytes& operator=(SecureBytes&& other) noexcept;
  ~SecureBytes();

  std::uint8_t* data() noexcept;
  const std::uint8_t* data() const noexcept;
  std::size_t size() const noexcept;
  bool empty() const noexcept;
  void resize(std::size_t size);
  void clear() noexcept;

  std::span<std::uint8_t> span() noexcept;
  std::span<const std::uint8_t> span() const noexcept;
  std::vector<std::uint8_t>& vec() noexcept;
  const std::vector<std::uint8_t>& vec() const noexcept;

 private:
  std::vector<std::uint8_t> bytes_;
};

class SecureString {
 public:
  SecureString() = default;
  explicit SecureString(std::string value);
  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;
  SecureString(SecureString&& other) noexcept;
  SecureString& operator=(SecureString&& other) noexcept;
  ~SecureString();

  const std::string& str() const noexcept;
  bool empty() const noexcept;
  void clear() noexcept;

 private:
  std::string value_;
};

using Bytes = std::vector<std::uint8_t>;
using Hash32 = std::array<std::uint8_t, 32>;
using Block16 = std::array<std::uint8_t, 16>;

}  // namespace encrylib
