#include "encrylib/sm3.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace encrylib {

namespace {

constexpr std::array<std::uint32_t, 8> kIv = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU};

constexpr std::uint32_t rotl(std::uint32_t value, int bits) noexcept {
  bits &= 31;
  if (bits == 0) {
    return value;
  }
  return (value << bits) | (value >> (32 - bits));
}

constexpr std::array<std::uint32_t, 64> make_tj_rot() {
  std::array<std::uint32_t, 64> out{};
  for (std::size_t j = 0; j < out.size(); ++j) {
    const auto tj = (j <= 15) ? 0x79cc4519U : 0x7a879d8aU;
    out[j] = rotl(tj, static_cast<int>(j % 32U));
  }
  return out;
}

constexpr auto kTjRot = make_tj_rot();

constexpr std::uint32_t p0(std::uint32_t x) noexcept {
  return x ^ rotl(x, 9) ^ rotl(x, 17);
}

constexpr std::uint32_t p1(std::uint32_t x) noexcept {
  return x ^ rotl(x, 15) ^ rotl(x, 23);
}

constexpr std::uint32_t ff0(std::uint32_t x,
                            std::uint32_t y,
                            std::uint32_t z) noexcept {
  return x ^ y ^ z;
}

constexpr std::uint32_t ff1(std::uint32_t x,
                            std::uint32_t y,
                            std::uint32_t z) noexcept {
  return (x & y) | (x & z) | (y & z);
}

constexpr std::uint32_t gg0(std::uint32_t x,
                            std::uint32_t y,
                            std::uint32_t z) noexcept {
  return x ^ y ^ z;
}

constexpr std::uint32_t gg1(std::uint32_t x,
                            std::uint32_t y,
                            std::uint32_t z) noexcept {
  return (x & y) | (~x & z);
}

std::uint32_t read_be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) |
         static_cast<std::uint32_t>(bytes[3]);
}

void write_be32(std::uint32_t value, std::uint8_t* out) {
  out[0] = static_cast<std::uint8_t>((value >> 24) & 0xffU);
  out[1] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
  out[2] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
  out[3] = static_cast<std::uint8_t>(value & 0xffU);
}

std::uint8_t hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint8_t>(10 + c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<std::uint8_t>(10 + c - 'A');
  }
  throw std::runtime_error("invalid hexadecimal character");
}

}  // namespace

Sm3::Sm3() { reset(); }

void Sm3::reset() {
  state_ = kIv;
  buffer_.fill(0);
  buffer_size_ = 0;
  total_bytes_ = 0;
}

void Sm3::update(const std::uint8_t* data, std::size_t size) {
  update(std::span<const std::uint8_t>(data, size));
}

void Sm3::update(std::span<const std::uint8_t> data) {
  total_bytes_ += data.size();
  if (buffer_size_ > 0) {
    const auto needed = buffer_.size() - buffer_size_;
    const auto take = std::min(needed, data.size());
    std::copy_n(data.data(), take, buffer_.data() + buffer_size_);
    buffer_size_ += take;
    data = data.subspan(take);
    if (buffer_size_ == buffer_.size()) {
      compress(buffer_.data());
      buffer_size_ = 0;
    }
  }

  while (data.size() >= buffer_.size()) {
    compress(data.data());
    data = data.subspan(buffer_.size());
  }

  if (!data.empty()) {
    std::copy(data.begin(), data.end(), buffer_.begin());
    buffer_size_ = data.size();
  }
}

Hash32 Sm3::final() {
  const std::uint64_t bit_len = total_bytes_ * 8U;
  buffer_[buffer_size_++] = 0x80U;

  if (buffer_size_ > 56) {
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
              buffer_.end(), 0);
    compress(buffer_.data());
    buffer_size_ = 0;
  }

  std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
            buffer_.begin() + 56, 0);
  for (int i = 0; i < 8; ++i) {
    buffer_[56 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((bit_len >> (56 - i * 8)) & 0xffU);
  }
  compress(buffer_.data());

  Hash32 out{};
  for (std::size_t i = 0; i < state_.size(); ++i) {
    write_be32(state_[i], out.data() + i * 4);
  }
  reset();
  return out;
}

void Sm3::compress(const std::uint8_t block[64]) {
  std::array<std::uint32_t, 68> w;
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = read_be32(block + i * 4);
  }
  for (std::size_t i = 16; i < 68; ++i) {
    w[i] = p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^
           rotl(w[i - 13], 7) ^ w[i - 6];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t j = 0; j < 16; ++j) {
    const std::uint32_t a12 = rotl(a, 12);
    const std::uint32_t ss1 = rotl(a12 + e + kTjRot[j], 7);
    const std::uint32_t ss2 = ss1 ^ a12;
    const std::uint32_t tt1 = ff0(a, b, c) + d + ss2 + (w[j] ^ w[j + 4]);
    const std::uint32_t tt2 = gg0(e, f, g) + h + ss1 + w[j];
    d = c;
    c = rotl(b, 9);
    b = a;
    a = tt1;
    h = g;
    g = rotl(f, 19);
    f = e;
    e = p0(tt2);
  }

  for (std::size_t j = 16; j < 64; ++j) {
    const std::uint32_t a12 = rotl(a, 12);
    const std::uint32_t ss1 = rotl(a12 + e + kTjRot[j], 7);
    const std::uint32_t ss2 = ss1 ^ a12;
    const std::uint32_t tt1 = ff1(a, b, c) + d + ss2 + (w[j] ^ w[j + 4]);
    const std::uint32_t tt2 = gg1(e, f, g) + h + ss1 + w[j];
    d = c;
    c = rotl(b, 9);
    b = a;
    a = tt1;
    h = g;
    g = rotl(f, 19);
    f = e;
    e = p0(tt2);
  }

  state_[0] ^= a;
  state_[1] ^= b;
  state_[2] ^= c;
  state_[3] ^= d;
  state_[4] ^= e;
  state_[5] ^= f;
  state_[6] ^= g;
  state_[7] ^= h;
}

Hash32 sm3(std::span<const std::uint8_t> data) {
  Sm3 ctx;
  ctx.update(data);
  return ctx.final();
}

Hash32 sm3_string(const std::string& data) {
  return sm3(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

std::string hex_encode(std::span<const std::uint8_t> data) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : data) {
    out << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return out.str();
}

Bytes hex_decode(const std::string& hex) {
  if ((hex.size() % 2) != 0) {
    throw std::runtime_error("hexadecimal string must have even length");
  }
  Bytes out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(
        (hex_value(hex[i * 2]) << 4) | hex_value(hex[i * 2 + 1]));
  }
  return out;
}

}  // namespace encrylib
