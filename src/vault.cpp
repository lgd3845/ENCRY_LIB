#include "encrylib/vault.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <system_error>

#include "encrylib/crypto.h"
#include "encrylib/hmac_sm3.h"
#include "encrylib/sm3.h"
#include "encrylib/util.h"

namespace encrylib {

namespace {

constexpr std::string_view kMetaMagic = "ELIBMETA1";
constexpr std::string_view kManifestMagic = "ELIBMAN1";
constexpr std::string_view kManifestPlainMagic = "ELIBMPL1";
constexpr std::string_view kObjectMagic = "ELIBOBJ1";
constexpr std::uint32_t kMinIterations = 10000;
constexpr std::uint32_t kMaxEntries = 1000000;

std::span<const std::uint8_t> str_bytes(std::string_view s) {
  return std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

void append_string(Bytes& out, std::string_view value) {
  append_u32(out, static_cast<std::uint32_t>(value.size()));
  append_bytes(out, str_bytes(value));
}

std::string read_string(std::span<const std::uint8_t> bytes,
                        std::size_t& offset) {
  const auto size = read_u32(bytes, offset);
  const auto value = read_span(bytes, offset, size);
  return std::string(reinterpret_cast<const char*>(value.data()), value.size());
}

void append_blob(Bytes& out, const EncryptedBlob& blob) {
  append_bytes(out, blob.nonce);
  append_u32(out, static_cast<std::uint32_t>(blob.ciphertext.size()));
  append_bytes(out, blob.ciphertext);
  append_bytes(out, blob.tag);
}

EncryptedBlob read_blob(std::span<const std::uint8_t> bytes,
                        std::size_t& offset) {
  EncryptedBlob blob;
  const auto nonce = read_span(bytes, offset, blob.nonce.size());
  std::copy(nonce.begin(), nonce.end(), blob.nonce.begin());
  const auto cipher_size = read_u32(bytes, offset);
  const auto ciphertext = read_span(bytes, offset, cipher_size);
  blob.ciphertext.assign(ciphertext.begin(), ciphertext.end());
  const auto tag = read_span(bytes, offset, blob.tag.size());
  std::copy(tag.begin(), tag.end(), blob.tag.begin());
  return blob;
}

void append_magic(Bytes& out, std::string_view magic) {
  append_bytes(out, str_bytes(magic));
}

void expect_magic(std::span<const std::uint8_t> bytes,
                  std::size_t& offset,
                  std::string_view magic) {
  const auto actual = read_span(bytes, offset, magic.size());
  if (!std::equal(actual.begin(), actual.end(), magic.begin(), magic.end())) {
    throw std::runtime_error("invalid vault file magic");
  }
}

Bytes meta_aad(std::uint32_t iterations, std::span<const std::uint8_t> salt) {
  Bytes aad;
  append_string(aad, "meta-master-key-v1");
  append_u32(aad, iterations);
  append_u32(aad, static_cast<std::uint32_t>(salt.size()));
  append_bytes(aad, salt);
  return aad;
}

Bytes manifest_aad() {
  Bytes aad;
  append_string(aad, "manifest-v1");
  return aad;
}

Bytes wrap_aad(const std::string& id) {
  Bytes aad;
  append_string(aad, "file-key-wrap-v1");
  append_string(aad, id);
  return aad;
}

Bytes object_aad(const FileEntry& entry) {
  Bytes aad;
  append_string(aad, "file-content-v1");
  append_string(aad, entry.id);
  append_string(aad, entry.name);
  append_u64(aad, entry.size);
  append_u64(aad, entry.added_unix_seconds);
  return aad;
}

Bytes serialize_manifest_plain(const std::vector<FileEntry>& entries) {
  Bytes out;
  append_magic(out, kManifestPlainMagic);
  append_u32(out, static_cast<std::uint32_t>(entries.size()));
  for (const auto& entry : entries) {
    append_string(out, entry.id);
    append_string(out, entry.name);
    append_u64(out, entry.size);
    append_u64(out, entry.added_unix_seconds);
  }
  return out;
}

std::vector<FileEntry> parse_manifest_plain(std::span<const std::uint8_t> bytes) {
  std::size_t offset = 0;
  expect_magic(bytes, offset, kManifestPlainMagic);
  const auto count = read_u32(bytes, offset);
  if (count > kMaxEntries) {
    throw std::runtime_error("manifest contains too many entries");
  }
  std::vector<FileEntry> entries;
  entries.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    FileEntry entry;
    entry.id = read_string(bytes, offset);
    entry.name = read_string(bytes, offset);
    entry.size = read_u64(bytes, offset);
    entry.added_unix_seconds = read_u64(bytes, offset);
    if (entry.id.empty() || entry.name.empty()) {
      throw std::runtime_error("manifest contains invalid entry");
    }
    entries.push_back(std::move(entry));
  }
  if (offset != bytes.size()) {
    throw std::runtime_error("manifest has trailing data");
  }
  return entries;
}

Bytes serialize_manifest_file(const EncryptedBlob& blob) {
  Bytes out;
  append_magic(out, kManifestMagic);
  append_blob(out, blob);
  return out;
}

EncryptedBlob parse_manifest_file(std::span<const std::uint8_t> bytes) {
  std::size_t offset = 0;
  expect_magic(bytes, offset, kManifestMagic);
  auto blob = read_blob(bytes, offset);
  if (offset != bytes.size()) {
    throw std::runtime_error("manifest file has trailing data");
  }
  return blob;
}

Bytes serialize_object_file(const EncryptedBlob& wrapped_key,
                            const EncryptedBlob& content) {
  Bytes out;
  append_magic(out, kObjectMagic);
  append_blob(out, wrapped_key);
  append_blob(out, content);
  return out;
}

std::pair<EncryptedBlob, EncryptedBlob> parse_object_file(
    std::span<const std::uint8_t> bytes) {
  std::size_t offset = 0;
  expect_magic(bytes, offset, kObjectMagic);
  auto wrapped_key = read_blob(bytes, offset);
  auto content = read_blob(bytes, offset);
  if (offset != bytes.size()) {
    throw std::runtime_error("object file has trailing data");
  }
  return {std::move(wrapped_key), std::move(content)};
}

std::uint64_t now_unix_seconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string make_object_id() {
  const auto id = random_bytes(16);
  return hex_encode(id);
}

void derive_vault_keys(std::span<const std::uint8_t> master_key,
                       Hash32& manifest_enc,
                       Hash32& manifest_mac,
                       Hash32& wrap_enc,
                       Hash32& wrap_mac) {
  manifest_enc = derive_key32(master_key, "vault-manifest-encryption-key-v1");
  manifest_mac = derive_key32(master_key, "vault-manifest-mac-key-v1");
  wrap_enc = derive_key32(master_key, "vault-file-key-wrap-encryption-key-v1");
  wrap_mac = derive_key32(master_key, "vault-file-key-wrap-mac-key-v1");
}

void derive_file_keys(std::span<const std::uint8_t> file_key,
                      Hash32& content_enc,
                      Hash32& content_mac) {
  content_enc = derive_key32(file_key, "file-content-encryption-key-v1");
  content_mac = derive_key32(file_key, "file-content-mac-key-v1");
}

Bytes password_bytes(const SecureString& password) {
  return Bytes(password.str().begin(), password.str().end());
}

SecureBytes derive_password_key(const SecureString& password,
                                std::span<const std::uint8_t> salt,
                                std::uint32_t iterations) {
  auto pw = password_bytes(password);
  auto key = pbkdf2_hmac_sm3(pw, salt, iterations, 32);
  secure_zero(pw.data(), pw.size());
  return key;
}

Bytes serialize_meta_file(std::uint32_t iterations,
                          std::span<const std::uint8_t> salt,
                          const EncryptedBlob& master_blob) {
  Bytes out;
  append_magic(out, kMetaMagic);
  append_u32(out, iterations);
  append_u32(out, static_cast<std::uint32_t>(salt.size()));
  append_bytes(out, salt);
  append_blob(out, master_blob);
  return out;
}

struct MetaFile {
  std::uint32_t iterations = 0;
  Bytes salt;
  EncryptedBlob master_blob;
};

MetaFile parse_meta_file(std::span<const std::uint8_t> bytes) {
  std::size_t offset = 0;
  expect_magic(bytes, offset, kMetaMagic);
  MetaFile meta;
  meta.iterations = read_u32(bytes, offset);
  if (meta.iterations < kMinIterations) {
    throw std::runtime_error("vault KDF iteration count is too low or corrupt");
  }
  const auto salt_size = read_u32(bytes, offset);
  if (salt_size < 16 || salt_size > 1024) {
    throw std::runtime_error("invalid vault salt size");
  }
  const auto salt = read_span(bytes, offset, salt_size);
  meta.salt.assign(salt.begin(), salt.end());
  meta.master_blob = read_blob(bytes, offset);
  if (offset != bytes.size()) {
    throw std::runtime_error("metadata file has trailing data");
  }
  return meta;
}

}  // namespace

Vault::Vault(std::filesystem::path root) : root_(std::move(root)) {}

void Vault::init(const std::filesystem::path& root,
                 const SecureString& password,
                 const VaultConfig& config) {
  if (password.empty()) {
    throw std::runtime_error("password must not be empty");
  }
  if (config.kdf_iterations < kMinIterations) {
    throw std::runtime_error("KDF iterations must be at least " +
                             std::to_string(kMinIterations));
  }

  Vault vault(root);
  ensure_directory(vault.root_);
  ensure_directory(vault.objects_dir());
  if (std::filesystem::exists(vault.meta_path())) {
    throw std::runtime_error("vault already exists: " + root.string());
  }

  vault.master_key_ = SecureBytes(random_bytes(32));
  derive_vault_keys(vault.master_key_.span(), vault.manifest_enc_key_,
                    vault.manifest_mac_key_, vault.wrap_enc_key_,
                    vault.wrap_mac_key_);

  auto salt = random_bytes(32);
  auto password_key = derive_password_key(password, salt, config.kdf_iterations);
  auto meta_enc = derive_key32(password_key.span(), "meta-encryption-key-v1");
  auto meta_mac = derive_key32(password_key.span(), "meta-mac-key-v1");
  auto aad = meta_aad(config.kdf_iterations, salt);
  auto master_blob =
      encrypt_blob(meta_enc, meta_mac, vault.master_key_.span(), aad);
  const auto meta = serialize_meta_file(config.kdf_iterations, salt, master_blob);
  write_file_atomic(vault.meta_path(), meta);
  vault.save_manifest();

  secure_zero(meta_enc.data(), meta_enc.size());
  secure_zero(meta_mac.data(), meta_mac.size());
  secure_zero(salt.data(), salt.size());
  secure_zero(aad.data(), aad.size());
}

Vault::Vault(const std::filesystem::path& root, const SecureString& password)
    : root_(root) {
  load(password);
  load_manifest();
}

Vault::~Vault() {
  secure_zero(manifest_enc_key_.data(), manifest_enc_key_.size());
  secure_zero(manifest_mac_key_.data(), manifest_mac_key_.size());
  secure_zero(wrap_enc_key_.data(), wrap_enc_key_.size());
  secure_zero(wrap_mac_key_.data(), wrap_mac_key_.size());
}

std::vector<FileEntry> Vault::list() const { return entries_; }

void Vault::add_file(const std::filesystem::path& source,
                     const std::string& stored_name,
                     bool keep_source) {
  if (!std::filesystem::is_regular_file(source)) {
    throw std::runtime_error("source is not a regular file: " + source.string());
  }
  FileEntry entry;
  entry.id = make_object_id();
  entry.name = sanitize_name(source, stored_name);
  entry.size = static_cast<std::uint64_t>(std::filesystem::file_size(source));
  entry.added_unix_seconds = now_unix_seconds();
  if (find_entry(entry.name) != nullptr) {
    throw std::runtime_error("vault already contains a file named: " +
                             entry.name);
  }
  while (std::filesystem::exists(object_path(entry.id))) {
    entry.id = make_object_id();
  }

  const auto plaintext = read_file(source);
  SecureBytes file_key(random_bytes(32));
  Hash32 content_enc{};
  Hash32 content_mac{};
  derive_file_keys(file_key.span(), content_enc, content_mac);

  auto content_aad = object_aad(entry);
  auto content = encrypt_blob(content_enc, content_mac, plaintext, content_aad);
  auto key_aad = wrap_aad(entry.id);
  auto wrapped_key =
      encrypt_blob(wrap_enc_key_, wrap_mac_key_, file_key.span(), key_aad);
  const auto object = serialize_object_file(wrapped_key, content);
  const auto path = object_path(entry.id);
  write_file_atomic(path, object);

  entries_.push_back(std::move(entry));
  try {
    save_manifest();
  } catch (...) {
    entries_.pop_back();
    std::error_code ec;
    std::filesystem::remove(path, ec);
    throw;
  }

  if (!keep_source) {
    std::error_code ec;
    std::filesystem::remove(source, ec);
    if (ec) {
      throw std::runtime_error("file was encrypted but source removal failed: " +
                               ec.message());
    }
  }

  secure_zero(content_enc.data(), content_enc.size());
  secure_zero(content_mac.data(), content_mac.size());
  secure_zero(content_aad.data(), content_aad.size());
  secure_zero(key_aad.data(), key_aad.size());
}

void Vault::extract_file(const std::string& stored_name,
                         const std::filesystem::path& destination,
                         bool remove_after_extract) {
  const auto* entry = find_entry(stored_name);
  if (entry == nullptr) {
    throw std::runtime_error("vault does not contain: " + stored_name);
  }
  const auto object = read_file(object_path(entry->id));
  auto [wrapped_key, content] = parse_object_file(object);

  auto key_aad = wrap_aad(entry->id);
  auto file_key_bytes =
      decrypt_blob(wrap_enc_key_, wrap_mac_key_, wrapped_key, key_aad);
  SecureBytes file_key(std::move(file_key_bytes));
  Hash32 content_enc{};
  Hash32 content_mac{};
  derive_file_keys(file_key.span(), content_enc, content_mac);

  auto content_aad = object_aad(*entry);
  auto plaintext = decrypt_blob(content_enc, content_mac, content, content_aad);
  if (plaintext.size() != entry->size) {
    throw std::runtime_error("decrypted file size does not match manifest");
  }

  std::filesystem::path output = destination;
  if (output.empty() || std::filesystem::is_directory(output)) {
    output /= entry->name;
  }
  write_file_atomic(output, plaintext);

  if (remove_after_extract) {
    delete_file(stored_name);
  }

  secure_zero(content_enc.data(), content_enc.size());
  secure_zero(content_mac.data(), content_mac.size());
  secure_zero(content_aad.data(), content_aad.size());
  secure_zero(key_aad.data(), key_aad.size());
}

void Vault::delete_file(const std::string& stored_name) {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const FileEntry& e) { return e.name == stored_name; });
  if (it == entries_.end()) {
    throw std::runtime_error("vault does not contain: " + stored_name);
  }
  const auto object = object_path(it->id);
  const auto old = entries_;
  entries_.erase(it);
  try {
    save_manifest();
  } catch (...) {
    entries_ = old;
    throw;
  }
  std::error_code ec;
  std::filesystem::remove(object, ec);
  if (ec) {
    throw std::runtime_error("failed to remove object file: " + ec.message());
  }
}

void Vault::load(const SecureString& password) {
  if (password.empty()) {
    throw std::runtime_error("password must not be empty");
  }
  const auto meta_bytes = read_file(meta_path());
  auto meta = parse_meta_file(meta_bytes);
  auto password_key = derive_password_key(password, meta.salt, meta.iterations);
  auto meta_enc = derive_key32(password_key.span(), "meta-encryption-key-v1");
  auto meta_mac = derive_key32(password_key.span(), "meta-mac-key-v1");
  auto aad = meta_aad(meta.iterations, meta.salt);
  auto master = decrypt_blob(meta_enc, meta_mac, meta.master_blob, aad);
  if (master.size() != 32) {
    throw std::runtime_error("invalid decrypted master key size");
  }
  master_key_ = SecureBytes(std::move(master));
  derive_vault_keys(master_key_.span(), manifest_enc_key_, manifest_mac_key_,
                    wrap_enc_key_, wrap_mac_key_);

  secure_zero(meta_enc.data(), meta_enc.size());
  secure_zero(meta_mac.data(), meta_mac.size());
  secure_zero(meta.salt.data(), meta.salt.size());
  secure_zero(aad.data(), aad.size());
}

void Vault::load_manifest() {
  if (!std::filesystem::exists(manifest_path())) {
    entries_.clear();
    return;
  }
  const auto bytes = read_file(manifest_path());
  auto blob = parse_manifest_file(bytes);
  const auto aad = manifest_aad();
  const auto plain = decrypt_blob(manifest_enc_key_, manifest_mac_key_, blob, aad);
  entries_ = parse_manifest_plain(plain);
}

void Vault::save_manifest() {
  const auto plain = serialize_manifest_plain(entries_);
  const auto aad = manifest_aad();
  const auto blob = encrypt_blob(manifest_enc_key_, manifest_mac_key_, plain, aad);
  const auto file = serialize_manifest_file(blob);
  write_file_atomic(manifest_path(), file);
}

std::filesystem::path Vault::meta_path() const { return root_ / "vault.meta"; }

std::filesystem::path Vault::manifest_path() const {
  return root_ / "manifest.bin";
}

std::filesystem::path Vault::objects_dir() const { return root_ / "objects"; }

std::filesystem::path Vault::object_path(const std::string& id) const {
  return objects_dir() / (id + ".obj");
}

FileEntry* Vault::find_entry(const std::string& name) {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const FileEntry& e) { return e.name == name; });
  return it == entries_.end() ? nullptr : &(*it);
}

const FileEntry* Vault::find_entry(const std::string& name) const {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const FileEntry& e) { return e.name == name; });
  return it == entries_.end() ? nullptr : &(*it);
}

}  // namespace encrylib
