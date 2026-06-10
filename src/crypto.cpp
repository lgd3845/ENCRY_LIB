#include "encrylib/crypto.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <sys/random.h>
#include <unistd.h>

#include "encrylib/hmac_sm3.h"
#include "encrylib/util.h"

namespace encrylib {

namespace {

constexpr std::string_view kMacDomain = "ENCRY_LIB-AEAD-SM4CTR-HSM3-v1";

std::span<const std::uint8_t> str_bytes(std::string_view s) {
  return std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

std::array<std::uint8_t, 8> be64(std::uint64_t value) {
  std::array<std::uint8_t, 8> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (56U - i * 8U)) & 0xffU);
  }
  return out;
}

void fill_random_getrandom(std::span<std::uint8_t> out) {
  while (!out.empty()) {
    const ssize_t n = getrandom(out.data(), out.size(), 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw std::runtime_error("getrandom failed: " + std::string(std::strerror(errno)));
    }
    out = out.subspan(static_cast<std::size_t>(n));
  }
}

void fill_random_urandom(std::span<std::uint8_t> out) {
  std::ifstream input("/dev/urandom", std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open /dev/urandom");
  }
  if (!out.empty()) {
    input.read(reinterpret_cast<char*>(out.data()),
               static_cast<std::streamsize>(out.size()));
    if (!input) {
      throw std::runtime_error("failed to read /dev/urandom");
    }
  }
}

Block16 sm4_key16(std::span<const std::uint8_t> key) {
  if (key.size() < 16) {
    throw std::runtime_error("SM4 encryption key must be at least 16 bytes");
  }
  Block16 out{};
  std::copy_n(key.begin(), out.size(), out.begin());
  return out;
}

Hash32 compute_tag(std::span<const std::uint8_t> mac_key,
                   const Block16& nonce,
                   std::span<const std::uint8_t> ciphertext,
                   std::span<const std::uint8_t> aad) {
  HmacSm3 hmac(mac_key);
  hmac.update(str_bytes(kMacDomain));

  auto len = be64(static_cast<std::uint64_t>(aad.size()));
  hmac.update(len);
  hmac.update(aad);

  hmac.update(nonce);

  len = be64(static_cast<std::uint64_t>(ciphertext.size()));
  hmac.update(len);
  hmac.update(ciphertext);
  secure_zero(len.data(), len.size());
  return hmac.final();
}

}  // namespace

Bytes random_bytes(std::size_t size) {
  Bytes out(size);
  if (out.empty()) {
    return out;
  }
  try {
    fill_random_getrandom(out);
  } catch (const std::exception&) {
    fill_random_urandom(out);
  }
  return out;
}

Block16 random_block16() {
  const auto bytes = random_bytes(16);
  Block16 out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

Hash32 random_hash32() {
  const auto bytes = random_bytes(32);
  Hash32 out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

bool constant_time_equal(std::span<const std::uint8_t> a,
                         std::span<const std::uint8_t> b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

Bytes derive_bytes(std::span<const std::uint8_t> key,
                   const std::string& info,
                   std::size_t output_size) {
  return hkdf_sm3(key, str_bytes(info), output_size);
}

Hash32 derive_key32(std::span<const std::uint8_t> key,
                    const std::string& info) {
  auto derived = derive_bytes(key, info, 32);
  Hash32 out{};
  std::copy(derived.begin(), derived.end(), out.begin());
  secure_zero(derived.data(), derived.size());
  return out;
}

EncryptedBlob encrypt_blob(std::span<const std::uint8_t> encryption_key,
                           std::span<const std::uint8_t> mac_key,
                           std::span<const std::uint8_t> plaintext,
                           std::span<const std::uint8_t> aad) {
  EncryptedBlob blob;
  blob.nonce = random_block16();
  blob.ciphertext.resize(plaintext.size());
  auto key16 = sm4_key16(encryption_key);
  Sm4 sm4(key16);
  sm4.ctr_crypt(blob.nonce, plaintext, blob.ciphertext);
  blob.tag = compute_tag(mac_key, blob.nonce, blob.ciphertext, aad);
  secure_zero(key16.data(), key16.size());
  return blob;
}

Bytes decrypt_blob(std::span<const std::uint8_t> encryption_key,
                   std::span<const std::uint8_t> mac_key,
                   const EncryptedBlob& blob,
                   std::span<const std::uint8_t> aad) {
  const auto expected = compute_tag(mac_key, blob.nonce, blob.ciphertext, aad);
  if (!constant_time_equal(expected, blob.tag)) {
    throw std::runtime_error("authentication failed");
  }
  Bytes plaintext(blob.ciphertext.size());
  auto key16 = sm4_key16(encryption_key);
  Sm4 sm4(key16);
  sm4.ctr_crypt(blob.nonce, blob.ciphertext, plaintext);
  secure_zero(key16.data(), key16.size());
  return plaintext;
}

}  // namespace encrylib
