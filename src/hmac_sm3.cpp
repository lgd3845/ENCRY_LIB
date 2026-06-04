#include "encrylib/hmac_sm3.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

#include "encrylib/util.h"

namespace encrylib {

namespace {

constexpr std::size_t kSm3BlockSize = 64;
constexpr std::size_t kSm3DigestSize = 32;

}  // namespace

HmacSm3::HmacSm3(std::span<const std::uint8_t> key)
    : outer_pad_(kSm3BlockSize) {
  SecureBytes normalized(kSm3BlockSize);
  if (key.size() > kSm3BlockSize) {
    const auto digest = sm3(key);
    std::copy(digest.begin(), digest.end(), normalized.vec().begin());
  } else {
    std::copy(key.begin(), key.end(), normalized.vec().begin());
  }

  SecureBytes inner_pad(kSm3BlockSize);
  for (std::size_t i = 0; i < kSm3BlockSize; ++i) {
    inner_pad.vec()[i] = normalized.vec()[i] ^ 0x36U;
    outer_pad_.vec()[i] = normalized.vec()[i] ^ 0x5cU;
  }
  inner_.update(inner_pad.span());
}

void HmacSm3::update(std::span<const std::uint8_t> data) {
  inner_.update(data);
}

Hash32 HmacSm3::final() {
  const auto inner_digest = inner_.final();
  Sm3 outer;
  outer.update(outer_pad_.span());
  outer.update(inner_digest);
  return outer.final();
}

Hash32 hmac_sm3(std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> data) {
  HmacSm3 hmac(key);
  hmac.update(data);
  return hmac.final();
}

Bytes hkdf_sm3(std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> info,
               std::size_t output_size) {
  if (output_size > 255 * kSm3DigestSize) {
    throw std::runtime_error("HKDF output request is too large");
  }
  Bytes output;
  output.reserve(output_size);
  Hash32 previous{};
  std::uint8_t counter = 1;
  while (output.size() < output_size) {
    HmacSm3 hmac(key);
    if (counter != 1) {
      hmac.update(previous);
    }
    hmac.update(info);
    const std::array<std::uint8_t, 1> c{counter};
    hmac.update(c);
    previous = hmac.final();
    const auto take = std::min(previous.size(), output_size - output.size());
    output.insert(output.end(), previous.begin(),
                  previous.begin() + static_cast<std::ptrdiff_t>(take));
    ++counter;
  }
  secure_zero(previous.data(), previous.size());
  return output;
}

SecureBytes pbkdf2_hmac_sm3(std::span<const std::uint8_t> password,
                            std::span<const std::uint8_t> salt,
                            std::uint32_t iterations,
                            std::size_t output_size) {
  if (iterations == 0) {
    throw std::runtime_error("PBKDF2 iterations must be greater than zero");
  }
  const std::size_t blocks =
      (output_size + kSm3DigestSize - 1) / kSm3DigestSize;
  if (blocks > std::numeric_limits<std::uint32_t>::max()) {
    throw std::runtime_error("PBKDF2 output request is too large");
  }

  SecureBytes output(output_size);
  std::size_t written = 0;
  for (std::uint32_t block = 1; block <= blocks; ++block) {
    Bytes salt_block;
    salt_block.reserve(salt.size() + 4);
    append_bytes(salt_block, salt);
    append_u32(salt_block, block);

    Hash32 u = hmac_sm3(password, salt_block);
    Hash32 t = u;
    secure_zero(salt_block.data(), salt_block.size());

    for (std::uint32_t i = 1; i < iterations; ++i) {
      u = hmac_sm3(password, u);
      for (std::size_t j = 0; j < t.size(); ++j) {
        t[j] ^= u[j];
      }
    }

    const auto take = std::min(t.size(), output_size - written);
    std::copy_n(t.begin(), take, output.vec().begin() +
                                   static_cast<std::ptrdiff_t>(written));
    written += take;
    secure_zero(u.data(), u.size());
    secure_zero(t.data(), t.size());
  }
  return output;
}

}  // namespace encrylib
