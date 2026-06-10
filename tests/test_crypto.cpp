#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "encrylib/crypto.h"
#include "encrylib/hmac_sm3.h"
#include "encrylib/sm3.h"
#include "encrylib/sm4.h"
#include "encrylib/util.h"
#include "encrylib/vault.h"

namespace {

using namespace std::string_literals;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::span<const std::uint8_t> bytes_of(const std::string& s) {
  return std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

void test_sm3() {
  const auto digest = encrylib::sm3_string("abc");
  expect(encrylib::hex_encode(digest) ==
             "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
         "SM3 abc vector failed");

  std::string repeated;
  repeated.reserve(64);
  for (int i = 0; i < 16; ++i) {
    repeated += "abcd";
  }
  const auto digest2 = encrylib::sm3_string(repeated);
  expect(encrylib::hex_encode(digest2) ==
             "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
         "SM3 64-byte vector failed");
}

void test_sm4() {
  const auto key = encrylib::hex_decode("0123456789abcdeffedcba9876543210");
  const auto plain = encrylib::hex_decode("0123456789abcdeffedcba9876543210");
  encrylib::Block16 block{};
  std::copy(plain.begin(), plain.end(), block.begin());
  encrylib::Sm4 sm4(key);
  const auto encrypted = sm4.encrypt_block(block);
  expect(encrylib::hex_encode(encrypted) ==
             "681edf34d206965e86b3e94f536e4246",
         "SM4 block vector failed");
  const auto decrypted = sm4.decrypt_block(encrypted);
  expect(decrypted == block, "SM4 decrypt vector failed");
}

void test_sm4_ctr_parallel_roundtrip() {
  const auto key = encrylib::hex_decode("0123456789abcdeffedcba9876543210");
  encrylib::Block16 nonce{};
  for (std::size_t i = 0; i < nonce.size(); ++i) {
    nonce[i] = static_cast<std::uint8_t>(i * 17U + 3U);
  }

  constexpr std::size_t kPayloadSize = 20U * 1024U * 1024U + 37U;
  encrylib::Bytes plain(kPayloadSize);
  std::uint32_t state = 0x31415926U;
  for (auto& byte : plain) {
    state = state * 1103515245U + 12345U;
    byte = static_cast<std::uint8_t>(state >> 24);
  }

  encrylib::Bytes cipher(plain.size());
  encrylib::Bytes roundtrip(plain.size());
  encrylib::Sm4 sm4(key);
  sm4.ctr_crypt(nonce, plain, cipher);
  sm4.ctr_crypt(nonce, cipher, roundtrip);
  expect(roundtrip == plain, "SM4-CTR parallel roundtrip failed");
}

void test_authenticated_blob() {
  const auto enc_key = encrylib::random_bytes(32);
  const auto mac_key = encrylib::random_bytes(32);
  const std::string plain = "authenticated secret payload";
  const std::string aad = "blob-test";
  auto blob = encrylib::encrypt_blob(enc_key, mac_key, bytes_of(plain),
                                     bytes_of(aad));
  const auto roundtrip =
      encrylib::decrypt_blob(enc_key, mac_key, blob, bytes_of(aad));
  expect(std::string(roundtrip.begin(), roundtrip.end()) == plain,
         "authenticated blob roundtrip failed");
  blob.ciphertext[0] ^= 0x01U;
  bool failed = false;
  try {
    (void)encrylib::decrypt_blob(enc_key, mac_key, blob, bytes_of(aad));
  } catch (const std::exception&) {
    failed = true;
  }
  expect(failed, "tampered ciphertext was accepted");
}

void test_vault_roundtrip() {
  const auto base =
      std::filesystem::temp_directory_path() /
      ("encrylib-test-" + std::to_string(static_cast<long long>(getpid())));
  std::filesystem::remove_all(base);
  std::filesystem::create_directories(base);
  const auto vault_dir = base / "vault";
  const auto source = base / "sample.txt";
  const auto out_dir = base / "out";
  std::filesystem::create_directories(out_dir);

  const std::string payload =
      "SM4/SM3 vault roundtrip\nline two\nbinary:\0\1\2"s;
  encrylib::write_file_atomic(source, bytes_of(payload));

  encrylib::VaultConfig config;
  config.kdf_iterations = 10000;
  encrylib::SecureString password("unit-test-password");
  encrylib::Vault::init(vault_dir, password, config);

  encrylib::SecureString password2("unit-test-password");
  encrylib::Vault vault(vault_dir, password2);
  vault.add_file(source, "sample.txt", false);
  expect(!std::filesystem::exists(source), "add did not remove source file");
  auto entries = vault.list();
  expect(entries.size() == 1 && entries[0].name == "sample.txt",
         "vault list after add failed");

  vault.extract_file("sample.txt", out_dir, true);
  const auto recovered = encrylib::read_file(out_dir / "sample.txt");
  expect(std::string(recovered.begin(), recovered.end()) == payload,
         "vault extract payload mismatch");
  entries = vault.list();
  expect(entries.empty(), "extract did not remove vault entry");

  std::filesystem::remove_all(base);
}

}  // namespace

int main() {
  try {
    test_sm3();
    test_sm4();
    test_sm4_ctr_parallel_roundtrip();
    test_authenticated_blob();
    test_vault_roundtrip();
    std::cout << "all tests passed\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "test failure: " << e.what() << "\n";
    return 1;
  }
}
