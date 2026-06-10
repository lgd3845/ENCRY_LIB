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
double measure_seconds(Fn&& fn) {
  const auto start = std::chrono::steady_clock::now();
  fn();
  const auto end = std::chrono::steady_clock::now();
  return std::chrono::duration<double>(end - start).count();
}

bool use_gb_unit(std::size_t bytes) {
  return bytes >= 1'000'000'000ULL;
}

double display_size(std::size_t bytes) {
  const double scale = use_gb_unit(bytes) ? 1'000'000'000.0 : 1'000'000.0;
  return static_cast<double>(bytes) / scale;
}

const char* size_unit(std::size_t bytes) {
  return use_gb_unit(bytes) ? "GB" : "MB";
}

const char* rate_unit(std::size_t bytes) {
  return use_gb_unit(bytes) ? "GB/s" : "MB/s";
}

double display_rate(std::size_t bytes, double seconds) {
  return display_size(bytes) / seconds;
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
      512U * 1024U * 1024U,
      1'000'000'000U,
      2'000'000'000ULL,
      4'000'000'000ULL,
  };

  std::cout << "size_bytes,size_value,size_unit,encrypt_s,decrypt_s,"
               "encrypt_rate,decrypt_rate,rate_unit\n";
  std::cout << std::fixed << std::setprecision(3);
  for (const auto size : sizes) {
    auto payload = make_payload(size);
    const auto expected_size = payload.size();
    if (size <= 128U * 1024U * 1024U) {
      auto blob =
          encrylib::encrypt_blob(enc_key, mac_key, payload, bytes_of(aad));
      (void)encrylib::decrypt_blob(enc_key, mac_key, blob, bytes_of(aad));
    }

    encrylib::EncryptedBlob measured_blob;
    const double enc_s = measure_seconds([&] {
      measured_blob =
          encrylib::encrypt_blob(enc_key, mac_key, payload, bytes_of(aad));
    });
    std::vector<std::uint8_t>().swap(payload);

    const double dec_s = measure_seconds([&] {
      const auto plain =
          encrylib::decrypt_blob(enc_key, mac_key, measured_blob, bytes_of(aad));
      if (plain.size() != expected_size) {
        throw std::runtime_error("benchmark decrypt size mismatch");
      }
    });

    std::cout << size << "," << display_size(size) << "," << size_unit(size)
              << "," << enc_s << "," << dec_s << ","
              << display_rate(size, enc_s) << ","
              << display_rate(size, dec_s) << "," << rate_unit(size) << "\n";
  }
  return 0;
}
