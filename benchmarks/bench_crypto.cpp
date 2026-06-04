#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "encrylib/crypto.h"

namespace {

std::span<const std::uint8_t> bytes_of(const std::string& s) {
  return std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

template <typename Fn>
double measure_ms(Fn&& fn) {
  const auto start = std::chrono::steady_clock::now();
  fn();
  const auto end = std::chrono::steady_clock::now();
  return std::chrono::duration<double, std::milli>(end - start).count();
}

double mib_per_second(std::size_t bytes, double ms) {
  const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
  return mib / (ms / 1000.0);
}

std::vector<std::uint8_t> make_payload(std::size_t size) {
  std::vector<std::uint8_t> data(size);
  std::uint32_t state = 0x12345678U;
  for (auto& byte : data) {
    state = state * 1664525U + 1013904223U;
    byte = static_cast<std::uint8_t>(state >> 24);
  }
  return data;
}

}  // namespace

int main() {
  const auto enc_key = encrylib::random_bytes(32);
  const auto mac_key = encrylib::random_bytes(32);
  const std::string aad = "benchmark-aad";
  const std::vector<std::size_t> sizes = {
      1U * 1024U * 1024U,
      8U * 1024U * 1024U,
      32U * 1024U * 1024U,
      128U * 1024U * 1024U,
  };

  std::cout << "size_bytes,encrypt_ms,decrypt_ms,encrypt_mib_s,decrypt_mib_s\n";
  std::cout << std::fixed << std::setprecision(3);
  for (const auto size : sizes) {
    const auto payload = make_payload(size);
    auto blob = encrylib::encrypt_blob(enc_key, mac_key, payload, bytes_of(aad));
    (void)encrylib::decrypt_blob(enc_key, mac_key, blob, bytes_of(aad));

    encrylib::EncryptedBlob measured_blob;
    const double enc_ms = measure_ms([&] {
      measured_blob =
          encrylib::encrypt_blob(enc_key, mac_key, payload, bytes_of(aad));
    });
    const double dec_ms = measure_ms([&] {
      const auto plain =
          encrylib::decrypt_blob(enc_key, mac_key, measured_blob, bytes_of(aad));
      if (plain.size() != payload.size()) {
        throw std::runtime_error("benchmark decrypt size mismatch");
      }
    });

    std::cout << size << "," << enc_ms << "," << dec_ms << ","
              << mib_per_second(size, enc_ms) << ","
              << mib_per_second(size, dec_ms) << "\n";
  }
  return 0;
}
