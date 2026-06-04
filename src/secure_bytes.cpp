#include "encrylib/secure_bytes.h"

#include <cstring>
#include <utility>

namespace encrylib {

void secure_zero(void* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0) {
    return;
  }
#if defined(__STDC_LIB_EXT1__)
  (void)memset_s(data, size, 0, size);
#else
  volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(data);
  while (size-- > 0) {
    *p++ = 0;
  }
#endif
}

SecureBytes::SecureBytes(std::size_t size) : bytes_(size) {}

SecureBytes::SecureBytes(std::vector<std::uint8_t> bytes)
    : bytes_(std::move(bytes)) {}

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : bytes_(std::move(other.bytes_)) {
  other.clear();
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
  if (this != &other) {
    clear();
    bytes_ = std::move(other.bytes_);
    other.clear();
  }
  return *this;
}

SecureBytes::~SecureBytes() { clear(); }

std::uint8_t* SecureBytes::data() noexcept { return bytes_.data(); }

const std::uint8_t* SecureBytes::data() const noexcept { return bytes_.data(); }

std::size_t SecureBytes::size() const noexcept { return bytes_.size(); }

bool SecureBytes::empty() const noexcept { return bytes_.empty(); }

void SecureBytes::resize(std::size_t size) { bytes_.resize(size); }

void SecureBytes::clear() noexcept {
  if (!bytes_.empty()) {
    secure_zero(bytes_.data(), bytes_.size());
    bytes_.clear();
    bytes_.shrink_to_fit();
  }
}

std::span<std::uint8_t> SecureBytes::span() noexcept {
  return std::span<std::uint8_t>(bytes_.data(), bytes_.size());
}

std::span<const std::uint8_t> SecureBytes::span() const noexcept {
  return std::span<const std::uint8_t>(bytes_.data(), bytes_.size());
}

std::vector<std::uint8_t>& SecureBytes::vec() noexcept { return bytes_; }

const std::vector<std::uint8_t>& SecureBytes::vec() const noexcept {
  return bytes_;
}

SecureString::SecureString(std::string value) : value_(std::move(value)) {}

SecureString::SecureString(SecureString&& other) noexcept
    : value_(std::move(other.value_)) {
  other.clear();
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
  if (this != &other) {
    clear();
    value_ = std::move(other.value_);
    other.clear();
  }
  return *this;
}

SecureString::~SecureString() { clear(); }

const std::string& SecureString::str() const noexcept { return value_; }

bool SecureString::empty() const noexcept { return value_.empty(); }

void SecureString::clear() noexcept {
  if (!value_.empty()) {
    secure_zero(value_.data(), value_.size());
    value_.clear();
    value_.shrink_to_fit();
  }
}

}  // namespace encrylib
